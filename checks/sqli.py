'''SQLi detection module
Trying safe payloads to identify SQL injection vulnerabilities.'''

import re
import requests
from typing import Dict, Any

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"\"1",
    "' OR 'x'='x"
]

ERROR_PATTERNS = [
    re.compile(r"SQL syntax", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"syntax to use near", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"SQLITE\/JDBC", re.I),
    re.compile(r"odbc", re.I)

]

def detect_sqli(session: requests.Session, url: str, params: Dict[str, str]= None, data: Dict[str,str]= None, timeout=8) -> Dict[str, Any]:
    '''Detect SQLi vulnerabilities in the given URL with optional params and data.'''
    findings = {"url": url, "vulnerable": False, "evidence": []}
    params = params or {}
    data = data or {}

    try:
        baseline = session.get(url, params=params, timeout=timeout).text
    except Exception as e:
        findings["evidence"].append(f"Error fetching baseline: {str(e)}")
        return findings
    
    if params:
        for payload in SQLI_PAYLOADS:
            for p in params.keys():
                test_params = params.copy()
                if p != "__none__":
                    test_params[p] = payload
                try:
                    r = session.get(url, params = test_params, timeout=timeout)
                    txt = r.text
                except Exception as e:
                    findings["evidence"].append(f"Error testing param {p}: {str(e)}")
                    continue
                
                for pattern in ERROR_PATTERNS:
                    if pattern.search(txt):
                        findings["vulnerable"] = True
                        findings["evidence"].append(f"Param '{p}' with payload '{payload}' triggered error pattern '{pattern.pattern}'")
                if payload in txt and payload not in baseline:
                    findings["vulnerable"] = True
                    findings["evidence"].append(f"Param '{p}' with payload '{payload}' reflected in response")  
    if data:
        try:
            baseline_post = session.post(url, params=params, data=data, timeout=timeout).text
        except Exception as e:
            findings["evidence"].append(f"Error fetching POST baseline: {str(e)}")
            baseline_post = baseline
            
        for payload in SQLI_PAYLOADS:
            for f in data.keys():
                test_data = data.copy()
                test_data[f] = payload
                try:
                    r = session.post(url, params=params, data=test_data, timeout=timeout)
                    txt = r.text
                except Exception as e:
                    findings["evidence"].append(f"Error testing form field {f}: {str(e)}")
                    continue
                

                for pattern in ERROR_PATTERNS:
                    if pattern.search(txt):
                        findings["vulnerable"] = True
                        findings["evidence"].append(f"POST field '{f}' with payload '{payload}' triggered error: '{pattern.pattern}'")
                

                if payload in txt and payload not in baseline_post:
                    findings["vulnerable"] = True
                    findings["evidence"].append(f"POST field '{f}' with payload '{payload}' reflected in response")
    
    return findings
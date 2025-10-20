import re
import requests
from typing import Dict, Any


XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>"
]

DANGEROUS_TAGS = [
    # Payload appears in script tags
    re.compile(r"<script[^>]*>.*?alert.*?</script>", re.I | re.DOTALL),
    
    # Payload appears in event handlers
    re.compile(r"on\w+\s*=\s*['\"]?.*?alert.*?['\"]?", re.I),
    
    # Payload appears as unencoded HTML
    re.compile(r"<(img|iframe|svg|body|input|select|textarea)[^>]*>", re.I),
    
    # JavaScript protocol in href or src
    re.compile(r"(href|src)\s*=\s*['\"]?\s*javascript:", re.I)
]

def detect_xss(session: requests.Session, url: str, params: Dict[str, str]= None, data: Dict[str,str]= None, timeout=8) -> Dict[str, Any]:

    findings = {"url": url, "vulnerable": False, "evidence": []}
    params = params or {}
    data = data or {}

    try:
        baseline = session.get(url, params=params, timeout=timeout).text
    except Exception as e:
        findings["evidence"].append(f"Error fetching baseline: {str(e)}")
        return findings
    
    if params:
        for payload in XSS_PAYLOADS:
            for param_name in params.keys():
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    response = session.get(url, params=test_params, timeout=timeout)
                    response_text = response.text
                
                except Exception as e:
                    findings["evidence"].append(f"Error testing GET param {param_name}: {str(e)}")
                    continue

                if payload in response_text and payload not in baseline:
                    for pattern in DANGEROUS_TAGS:
                        if pattern.search(response_text):
                            findings["vulnerable"] = True
                            findings["evidence"].append(
                                f"GET parameter '{param_name}' reflects XSS payload '{payload[:50]}...' "
                                f"in dangerous context (pattern: {pattern.pattern[:50]})"
                            )
                            break

                    if "<script" in response_text.lower() and "alert" in response_text.lower():
                        findings["vulnerable"] = True
                        findings["evidence"].append(
                            f"GET parameter '{param_name}' reflects XSS payload '{payload[:50]}...' "
                        )
    if data:
        try:
            baseline_post = session.post(url, params=params, data=data, timeout=timeout).text
        except Exception as e:
            findings["evidence"].append(f"Error fetching POST baseline: {str(e)}")
            baseline_post = baseline
            
        for payload in XSS_PAYLOADS:
            for field_name in data.keys():
                test_data = data.copy()
                test_data[field_name] = payload

                try:
                    response = session.post(url, params=params, data=test_data, timeout=timeout)
                    response_text = response.text
                
                except Exception as e:
                    findings["evidence"].append(f"Error testing POST field {field_name}: {str(e)}")
                    continue

                if payload in response_text and payload not in baseline_post:
                    for pattern in DANGEROUS_TAGS:
                        if pattern.search(response_text):
                            findings["vulnerable"] = True
                            findings["evidence"].append(
                                f"POST field '{field_name}' reflects XSS payload '{payload[:50]}...' "
                                f"in dangerous context (pattern: {pattern.pattern[:50]})"
                            )
                            break

                    if "<script" in response_text.lower() and "alert" in response_text.lower():
                        findings["vulnerable"] = True
                        findings["evidence"].append(
                            f"POST field '{field_name}' reflects XSS payload '{payload[:50]}...'"
                        )
    return findings
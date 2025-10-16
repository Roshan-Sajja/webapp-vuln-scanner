import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from collections import deque


class Crawler:
    def __init__(self, start_url, max_depth=2, max_pages=50, same_origin=True, delay=0.3, progress_cb=None):
        self.start_url  = start_url.rstrip('/')
        self.base_origin = urlparse(self.start_url).netloc
        self.max_depth  = max_depth
        self.max_pages  = max_pages
        self.same_origin = same_origin
        self.delay      = delay
        self.progress_cb = progress_cb
        self.session    = requests.Session()
        self.session.headers.update({"User-Agent": "webapp-vuln-scanner/0.1(+https://github.com/Roshan-Sajja/webapp-vuln-scanner)"})
    
    def fetch_page(self, url):
        try:
            response = self.session.get(url, timeout=8, allow_redirects=True)
            ct = response.headers.get('Content-Type', '')
            if response.status_code !=200:
                return{"url": url, "status": response.status_code, "html": None}
            if 'text/html' not in ct:
                return{"url": url, "status": response.status_code, "html": None}
            
            return {"url": url, "status": response.status_code, "html": response.text}
        except requests.exceptions.RequestException as e:

            return {"url":url, "status": "error", "erorr": str(e), "html": None}
        


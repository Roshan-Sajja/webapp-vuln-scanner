import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
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
        
    def extract_links(self, page_html, base_url):
        soup = BeautifulSoup(page_html, 'lxml')
        links = set()
        for a in soup.find_all('a', href=True):
            href = a.get('href').strip()
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in ('http', 'https'):
                continue
            if parsed.fragment:
                absolute = absolute.split('#')[0]
            if self.same_origin and parsed.netloc != self.base_origin:
                continue
            links.add(absolute.rstrip('/'))
        return links
    
    def run(self):
        q = deque()
        q.append((self.start_url, 0))
        visited = set([self.start_url])
        results = []

        while q and len(results) < self.max_pages:
            url, depth = q.popleft()
            if depth > self.max_depth:
                continue

            if self.progress_cb:
                pct = int((len(results) / max(1, self.max_pages)) * 100)
                self.progress_cb(f"fetching: {url} (depth: {depth})", pct)

            page = self.fetch_page(url)
            page['depth'] = depth
            results.append(page)

            if page.get('html') and depth < self.max_depth:
                links = self.extract_links(page['html'], url)
                for link in links:
                    if link not in visited and len(visited) < self.max_pages:
                        visited.add(link)
                        q.append((link, depth + 1))
            time.sleep(self.delay)

        if self.progress_cb:
            self.progress_cb(f"Crawling completed: {len(results)} pages fetched", 100)
        return results
    
#local testing
if __name__ == '__main__':  
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    crawler = Crawler(
        target,
        max_depth=2,
        max_pages=50,
        same_origin=True,
        delay=0.3,
        progress_cb=lambda m, p: print(f"[{p:3d}%] {m}")
    )
    pages = crawler.run()
    print(f"Done. Indexed {len(pages)} pages.")
    for p in pages[:10]:
        print(p['url'], p['status'], "depth=", p.get('depth'))
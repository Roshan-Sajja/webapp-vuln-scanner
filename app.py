import os
import threading
import uuid
import time
import json
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context
from urllib.parse import urlparse, parse_qsl


load_dotenv()

from crawler import Crawler
from db import init_db, upsert_page, insert_findings
from checks import ALL_CHECKS

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev")

with app.app_context():
    init_db()                                   

JOBS = {}

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    target = request.form.get('target')
    if not target or not target.startswith(('http://', 'https://')):
        return "Invalid URL. Please include http:// or https://", 400
    
    selected = request.form.getlist('checks')

    checks_to_run = [c for c in ALL_CHECKS if c[0] in selected] or ALL_CHECKS

    max_depth = int(os.getenv("CRAWL_DEPTH", "3"))
    max_pages = int(os.getenv("MAX_PAGES", "50"))
    delay = float(os.getenv("CRAWL_DELAY", "0.3"))

    job_id = str(uuid.uuid4().hex)
    JOBS[job_id] = {
        "id": job_id,
        "status": "queued",
        "target": target,
        "pages": [],
        "progress": 0,
        "message": "Queued"
        }

    t = threading.Thread(target=run_scan, args=(job_id, target, checks_to_run, max_depth, max_pages, delay), daemon=True)
    t.start()

    return redirect(url_for('job_status', job_id=job_id))

def run_scan(job_id, target, checks_to_run, max_depth, max_pages, delay):

    job = JOBS[job_id]
    session = None
    
    try:
        # initialize the scanning job
        job["status"] = "running"
        job["progress"] = 0
        job["message"] = "Starting crawler"
        job["pages"] = []
        
        # set up the progress callback that the crawler will use
        def progress_cb(message, percent, pages=None):
            job["message"] = message
            job["progress"] = int(percent)
            if pages is not None:
                job["pages"] = pages
        
        # step 1: Crawl the target website to discover all pages
        crawler = Crawler(
            target, 
            max_depth=max_depth, 
            max_pages=max_pages, 
            same_origin=True,
            delay=delay,
            progress_cb=progress_cb
        )
        discovered_pages = crawler.run()

        # step 2: Scan each discovered page for vulnerabilities
        session = create_scan_session()
        total_pages = len(discovered_pages)
        
        for page_number, page_data in enumerate(discovered_pages, start=1):

            page_id = save_page_to_database(page_data)
            

            findings = run_vulnerability_checks(
                session=session,
                page_url=page_data.get("url"),
                checks=checks_to_run
            )
            

            if findings:
                insert_findings(page_id, findings)
            

            update_job_progress(job, page_data, page_number, total_pages)
        
        # step 3: Mark the job as completed
        job["status"] = "completed"
        job["message"] = "Scan complete"
        job["progress"] = 100
        
    except Exception as e:

        job["status"] = "error"
        job["message"] = f"Scan failed: {str(e)}"
        
    finally:

        if session:
            try:
                session.close()
            except:
                pass


def create_scan_session():
    import requests
    session = requests.Session()
    session.headers.update({"User-Agent": "webapp-vuln-scanner/0.1"})
    return session


def save_page_to_database(page_data):
    url = page_data.get("url")
    status = page_data.get("status")
    return upsert_page(url, status_code=status, content_type=None)


def run_vulnerability_checks(session, page_url, checks):
    findings = []
    timeout = int(os.getenv("REQUEST_TIMEOUT", "8"))

    parsed = urlparse(page_url or "")
    params = dict(parse_qsl(parsed.query)) if parsed.query else None
    
    for check_name, check_function in checks:
        try:
            # execute
            result = check_function(
                session, 
                page_url, 
                params=params, 
                data=None, 
                timeout=timeout
            )
            

            parsed_findings = parse_check_result(check_name, result)
            findings.extend(parsed_findings)
            
        except Exception as e:

            findings.append((check_name, "", f"Check error: {str(e)}"))
    
    return findings


def parse_check_result(check_name, result):
    findings = []
    

    if isinstance(result, dict):
        if result.get("vulnerable"):
            for evidence_item in result.get("evidence", []):
                findings.append((check_name, "", evidence_item))
    

    elif isinstance(result, list):
        for item in result:
            if len(item) == 3:

                findings.append((item[0], item[1], item[2]))
            elif len(item) == 2:

                findings.append((check_name, item[0], item[1]))
    
    return findings


def update_job_progress(job, page_data, current_page, total_pages):

    url = page_data.get("url")
    status = page_data.get("status")
    depth = page_data.get("depth", 0)
    
    # add this page to the list of scanned pages
    job["pages"].append({
        "url": url, 
        "status": status, 
        "depth": depth
    })
    
    # calculate and update progress percentage
    progress_percent = int((current_page / max(total_pages, 1)) * 100)
    job["progress"] = progress_percent
    job["message"] = f"Scanned {current_page}/{total_pages}: {url}"


def percent_done(current, total):
    return int((current / max(total, 1)) * 100)

@app.route('/job/<job_id>', methods=['GET'])
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "Job not found", 404
    
    vulnerabilities = []
    if job.get("status") == "completed":
        from db import get_findings_for_scan
        vulnerabilities = get_findings_for_scan(job_id, job.get("target"))

    return render_template('status.html', job=job, job_id=job_id, vulnerabilities=vulnerabilities)

@app.route('/stream/<job_id>')
def stream(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "Job not found", 404

    def event_stream():
        last_sent = None
        while True:
            j = JOBS.get(job_id)
            if not j:
                break
            data = {
                "status": j.get("status"),
                "progress": j.get("progress", 0),
                "message": j.get("message", ""),
                "pages": j.get("pages", []),
                "target": j.get("target")
            }

            if j.get("status") == "completed":
                from db import get_findings_for_scan
                vulns = get_findings_for_scan(job_id, j.get("target"))
                data["vulnerabilities"] = vulns

            payload = json.dumps(data)
            if payload != last_sent:
                yield f"data: {payload}\n\n"
                last_sent = payload
            if j.get("status") in ("completed", "error"):
                break
            time.sleep(0.5)
    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')
      


if __name__ == '__main__':
    app.run(debug=True)


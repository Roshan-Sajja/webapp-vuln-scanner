from flask import Flask, render_template
import threading, uuid
from crawler import Crawler
app = Flask(__name__)

JOBS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    target = request.form.get('target')
    if not target or not target.startswith(('http://', 'https://')):
        return "Invalid URL. Please include http:// or https://", 400
    
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {"status": "queued", "target": target, "pages":[]}

    t = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    t.start()

    return redirect(url_for('job_status', job_id=job_id))

def run_job(job_id):
    job = JOBS[job_id]
    job["status"] = "running"
    try:
        crawler = Crawler(job["target"], max_depth=2, max_pages=50, delay=0.3)
        pages = crawler.run()
        job["pages"] = pages
        job["status"] = "completed"
    except Exception as e:
        job["status"] = f"error: {e}"


@app.route('/job/<job_id>')
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "Job not found", 404
    return render_template('status.html', job=job, job_id=job_id)


if __name__ == '__main__':
    app.run(debug=True)


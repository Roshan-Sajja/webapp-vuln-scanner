from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context
import threading, uuid, json, time
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
    JOBS[job_id] = {
        "status": "queued", 
        "target": target, 
        "pages":[],
        "progress":0,
        "message":"Queued"
        }

    t = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    t.start()

    return redirect(url_for('job_status', job_id=job_id))

def run_job(job_id):
    job = JOBS[job_id]
    job.update({"status": "running", "progress": 0, "message": "Starting…"})

    def on_progress(message, percent):
        job.update({"message": message, "progress": int(percent)})
    try:
        crawler = Crawler(
            job["target"], 
            max_depth=2, 
            max_pages=50, 
            delay=0.3,
            progress_cb=on_progress
        )
        
        pages = crawler.run()
        job["pages"] = [
            {"url": p.get("url"), "status": p.get("status"), "depth": p.get("depth")}
            for p in pages
        ]
        job.update({"status": "completed", "progress": 100, "message": "Done"})
    except Exception as e:
        import traceback
        job.update({"status": "error", "message": f"Failed: {str(e)}", "error_detail": traceback.format_exc()})


@app.route('/job/<job_id>')
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "Job not found", 404
    return render_template('status.html', job=job, job_id=job_id)

@app.route('/stream/<job_id>')
def stream(job_id):
    def generate():
        last_progress = -1
        last_message = ""

        while True:
            job = JOBS.get(job_id)
            if not job:
                yield f"data: {json.dumps({'status':'error','message':'Job not found'})}\n\n"
                break

            current_progress = job.get('progress', 0)
            current_message = job.get('message', '')
            current_status = job.get('status', '')
            
            if current_progress != last_progress or current_message != last_message:

                data = {
                    'progress': current_progress,
                    'message': current_message,
                    'status': current_status,
                    'pages': job.get('pages', [])
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_message = current_message
                last_progress = current_progress
            if current_status in ['completed', 'error']:
                break
            time.sleep(0.5)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
        


if __name__ == '__main__':
    app.run(debug=True)


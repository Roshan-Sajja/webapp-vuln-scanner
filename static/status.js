const jobID = document.getElementById('job-data').dataset.jobId;
const eventSource = new EventSource(`/stream/${jobID}`);

eventSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    document.getElementById('status').textContent = data.status;
    document.getElementById('progress').textContent= data.progress;
    document.getElementById('message').textContent= data.message;

    if (data.status === 'completed' && data.pages && data.pages.length > 0) {
        const resultDiv = document.getElementById('results');

        let html = '<h2>Indexed Pages (first 20)</h2><ol id="page-list">';
        data.pages.slice(0, 20).forEach(page => {
            html += `<li>${page.url} - ${page.status} (Depth: ${page.depth})</li>`;
        });
        html += '</ol>';

        resultDiv.innerHTML = html;
    }
    if (data.status === 'completed' || data.status === 'error') {
        eventSource.close();
    }
};


eventSource.onerror = function(err) {
    console.error('SSE connection error:', err);
    eventSource.close();
    document.getElementById('message').textContent = 'Connection error. Please refresh the page.';
}
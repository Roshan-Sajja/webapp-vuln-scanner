
document.addEventListener('DOMContentLoaded', function() {
    
    // Now we know all HTML elements exist and can be safely accessed
    const jobDataEl = document.getElementById('job-data');
    
    // Add a safety check in case the element still doesn't exist
    if (!jobDataEl) {
        console.error('job-data element not found - cannot start SSE connection');
        return;
    }
    
    const jobID = jobDataEl.dataset.jobId;
    const eventSource = new EventSource(`/stream/${jobID}`);

    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        
        document.getElementById('status').textContent = data.status;
        document.getElementById('progress').textContent = data.progress;
        document.getElementById('message').textContent = data.message;

        if (data.pages && data.pages.length > 0) {
            updatePagesList(data.pages);
        }
        
        if (data.status === 'completed' && data.vulnerabilities) {
            displayVulnerabilities(data.vulnerabilities);
        }
        
        if (data.status === 'completed' || data.status === 'error') {
            eventSource.close();
        }
    };

    eventSource.onerror = function(err) {
        console.error('SSE connection error:', err);
        eventSource.close();
        document.getElementById('message').textContent = 'Connection error. Please refresh the page.';
    };

    function updatePagesList(pages) {
        const resultDiv = document.getElementById('results');
        

        if (!resultDiv) {
            console.error('results element not found');
            return;
        }
        
        let html = '<details>';
        html += '<summary class="pages-summary">Crawled Pages (' + pages.length + ' total)</summary>';
        html += '<ol id="pages-list">';
        
        pages.forEach(page => {
            html += '<li class="page-item">';
            html += '<code class="page-url">' + escapeHtml(page.url) + '</code> ';
            html += '<span class="page-status status-' + page.status + '">status ' + page.status + '</span> ';
            html += '<span class="page-depth">depth ' + page.depth + '</span>';
            html += '</li>';
        });
        
        html += '</ol></details>';
        resultDiv.innerHTML = html;
    }

    function displayVulnerabilities(vulnerabilities) {
        const vulnSection = document.getElementById('vulnerabilities-section');
        
        if (!vulnSection) {
            console.error('vulnerabilities-section element not found');
            return;
        }
        
        if (!vulnerabilities || vulnerabilities.length === 0) {
            vulnSection.innerHTML = 
                '<h2 class="success-header">No Vulnerabilities Found</h2>' +
                '<div class="success-message">' +
                '<p>Good news! The scan completed successfully and found no vulnerabilities.</p>' +
                '</div>';
            return;
        }
        
        let html = '<h2 class="vuln-header">Vulnerabilities Found</h2>';
        html += '<div class="vuln-summary">';
        html += '<p><strong>Summary:</strong> Found vulnerabilities on ' + vulnerabilities.length + ' page(s).</p>';
        html += '</div>';
        
        html += '<div id="vuln-list">';
        
        vulnerabilities.forEach(pageVulns => {
            html += '<article class="vuln-page">';
            html += '<h3 class="vuln-page-title">' + escapeHtml(pageVulns.url) + '</h3>';
            html += '<p class="page-meta">Status Code: ' + pageVulns.status_code + '</p>';
            
            pageVulns.findings.forEach(finding => {
                html += '<div class="vulnerability">';
                
                html += '<p class="vuln-type-label">';
                html += '<strong>Type:</strong> ';
                html += '<span class="vuln-type-badge">' + escapeHtml(finding.type) + '</span>';
                html += '</p>';
                
                if (finding.payload) {
                    html += '<p class="vuln-payload">';
                    html += '<strong>Payload:</strong> <code>' + escapeHtml(finding.payload) + '</code>';
                    html += '</p>';
                }
                
                html += '<details class="vuln-evidence">';
                html += '<summary><strong>Evidence</strong></summary>';
                html += '<div class="evidence-content">';
                html += '<pre>' + escapeHtml(finding.evidence) + '</pre>';
                html += '</div>';
                html += '</details>';
                
                if (finding.timestamp) {
                    html += '<p class="vuln-timestamp">';
                    html += '<em>Detected: ' + finding.timestamp + '</em>';
                    html += '</p>';
                }
                
                html += '</div>';
            });
            
            html += '</article>';
        });
        
        html += '</div>';
        vulnSection.innerHTML = html;
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

}); 
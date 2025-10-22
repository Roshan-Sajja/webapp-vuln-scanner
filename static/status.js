
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
    
    // First, let's count how many of each type of vulnerability we found
    // This gives users a quick overview before diving into details
    const vulnStats = calculateVulnerabilityStats(vulnerabilities);
    
    // Build a summary dashboard that shows the high-level picture
    let html = '<h2 class="vuln-header">Vulnerabilities Found</h2>';
    html += '<div class="vuln-summary">';
    html += '<p><strong>Total Issues:</strong> ' + vulnStats.totalFindings + ' findings across ' + vulnerabilities.length + ' page(s)</p>';
    html += '<div class="vuln-type-stats">';
    
    // Show a breakdown by vulnerability type
    for (const [vulnType, count] of Object.entries(vulnStats.byType)) {
        html += '<div class="stat-item">';
        html += '<span class="stat-label">' + escapeHtml(vulnType) + ':</span> ';
        html += '<span class="stat-count">' + count + '</span>';
        html += '</div>';
    }
    html += '</div>';
    html += '</div>';
    
    // Add filter buttons so users can focus on specific vulnerability types
    html += '<div class="vuln-filters">';
    html += '<button class="filter-btn active" data-filter="all">Show All</button>';
    for (const vulnType of Object.keys(vulnStats.byType)) {
        html += '<button class="filter-btn" data-filter="' + escapeHtml(vulnType) + '">' + escapeHtml(vulnType) + '</button>';
    }
    html += '</div>';
    
    // Now display the detailed findings, but make each page collapsible
    // This way users only expand the pages they want to investigate
    html += '<div id="vuln-list">';
    
    vulnerabilities.forEach((pageVulns, index) => {
        html += '<article class="vuln-page" data-page-index="' + index + '">';
        
        // The summary line shows the URL and count, acting as a preview
        // Users can click to expand and see the full details
        html += '<details class="page-details">';
        html += '<summary class="vuln-page-summary">';
        html += '<span class="summary-url">' + escapeHtml(pageVulns.url) + '</span>';
        html += '<span class="summary-count">(' + pageVulns.findings.length + ' finding';
        if (pageVulns.findings.length !== 1) html += 's';
        html += ')</span>';
        html += '</summary>';
        
        // The full details are hidden until the user expands this section
        html += '<div class="page-details-content">';
        html += '<p class="page-meta">Status Code: ' + pageVulns.status_code + '</p>';
        
        pageVulns.findings.forEach((finding, findingIndex) => {
            // Each vulnerability gets tagged with its type for filtering
            html += '<div class="vulnerability" data-vuln-type="' + escapeHtml(finding.type) + '">';
            
            html += '<p class="vuln-type-label">';
            html += '<strong>Type:</strong> ';
            html += '<span class="vuln-type-badge">' + escapeHtml(finding.type) + '</span>';
            html += '</p>';
            
            if (finding.payload) {
                html += '<p class="vuln-payload">';
                html += '<strong>Payload:</strong> <code>' + escapeHtml(finding.payload) + '</code>';
                html += '</p>';
            }
            
            // Evidence is in a nested collapsible section for even more control
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
        
        html += '</div>'; // Close page-details-content
        html += '</details>'; // Close page-details
        html += '</article>';
    });
    
    html += '</div>';
    vulnSection.innerHTML = html;
    
    // After creating the HTML, attach event listeners to make filtering work
    attachFilterListeners();
}

// This helper function counts up all the vulnerabilities by type
// It processes the data structure to give us statistics for the summary
function calculateVulnerabilityStats(vulnerabilities) {
    const stats = {
        totalFindings: 0,
        byType: {}
    };
    
    vulnerabilities.forEach(pageVulns => {
        pageVulns.findings.forEach(finding => {
            stats.totalFindings++;
            const type = finding.type;
            if (!stats.byType[type]) {
                stats.byType[type] = 0;
            }
            stats.byType[type]++;
        });
    });
    
    return stats;
}

// This function makes the filter buttons interactive
// When you click a button, it shows only vulnerabilities of that type
function attachFilterListeners() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filterType = this.getAttribute('data-filter');
            
            // Update which button looks active
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            // Show or hide vulnerabilities based on the selected filter
            const vulnerabilities = document.querySelectorAll('.vulnerability');
            vulnerabilities.forEach(vuln => {
                const vulnType = vuln.getAttribute('data-vuln-type');
                if (filterType === 'all' || vulnType === filterType) {
                    vuln.style.display = 'block';
                } else {
                    vuln.style.display = 'none';
                }
            });
            
            // Also manage the visibility of pages that have no visible findings after filtering
            const pages = document.querySelectorAll('.vuln-page');
            pages.forEach(page => {
                const visibleVulns = page.querySelectorAll('.vulnerability[style="display: block;"], .vulnerability:not([style*="display: none"])');
                if (filterType === 'all' || visibleVulns.length > 0) {
                    page.style.display = 'block';
                } else {
                    page.style.display = 'none';
                }
            });
        });
    });
}

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

}); 
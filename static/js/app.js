document.addEventListener('DOMContentLoaded', function() {
    const socket = io(); // Initialize Socket.IO client

    const resultsLog = document.getElementById('results-log');
    const packetDetailsDiv = document.getElementById('packet-details');
    const blockedIpsList = document.getElementById('blocked-ips-list');
    const alertsList = document.getElementById('alerts-list');

    let isFirstPacket = true;
    let countdownIntervals = {};

    // Listen for packet data from the server
    socket.on('packet_data_response', function(data) {
        console.log("Received data from backend:", data);

        if (isFirstPacket) {
            resultsLog.innerHTML = '';
            isFirstPacket = false;
        }

        if (data.error) {
            console.error('Server Error:', data.error);
            const errorEntry = document.createElement('p');
            errorEntry.className = 'text-danger';
            errorEntry.textContent = `An error occurred: ${data.error}`;
            resultsLog.prepend(errorEntry);
            return;
        }

        // ------------------------------
        // CREATE LOG ENTRY CONTAINER
        // ------------------------------
        const logEntry = document.createElement('div');
        logEntry.classList.add('log-entry');

        // ADD COLOR CLASS BASED ON ACTION
        if (data.action === "Allow") {
            logEntry.classList.add("allow");
        }
        else if (data.action === "Temporary Block") {
            logEntry.classList.add("temporary-block");
        }
        else if (data.action === "Block") {
            logEntry.classList.add("block");
        }

        // ------------------------------
        // SET ICONS
        // ------------------------------
        let iconClass = 'bi-question-circle'; // Default icon
        if (data.action === 'Allow') {
            iconClass = 'bi-check-circle-fill';
        }
        else if (data.action === 'Temporary Block') {
            iconClass = 'bi-exclamation-triangle-fill';
        }
        else if (data.action.includes('Block')) {
            iconClass = 'bi-shield-slash-fill';
        }

        // ------------------------------
        // BUILD LOG ENTRY HTML
        // ------------------------------
        logEntry.innerHTML = `
            <div class="log-icon">
                <i class="bi ${iconClass}"></i>
            </div>
            <div class="log-details">
                <div>
                    Prediction: <strong>${data.attack_prediction}</strong> from <strong>${data.details.src_ip}</strong>
                </div>
                <div>
                    Trust Score: <strong>${data.trust_score}</strong>
                </div>
            </div>
            <div class="action-display action-${data.action.toLowerCase().replace(/ /g, '-')}" >
                ${data.action}
            </div>
        `;

        resultsLog.prepend(logEntry);

        // ------------------------------
        // PACKET DETAILS SECTION
        // ------------------------------
        // Defensive check for data.details
        if (data.details && typeof data.details === 'object' && Object.keys(data.details).length > 0) {
            let detailsHtml = '<ul>';
            for (const [key, value] of Object.entries(data.details)) {
                detailsHtml += `<li><strong>${key}:</strong> ${value}</li>`;
            }
            detailsHtml += '</ul>';
            packetDetailsDiv.innerHTML = detailsHtml;
        } else {
            packetDetailsDiv.innerHTML = '<p class="text-muted">Details not available for this packet.</p>';
        }

        // Update alerts or blocked lists
        if (data.action === "Temporary Block" || data.action === "Block") {
            updateAlertsList();
            updateBlockedIpsList();
        }
    });

    // ------------------------------
    // UNBLOCK IP FUNCTION
    // ------------------------------
    window.unblockIp = function(ip) {
        fetch('/api/unblock_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip }),
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            updateBlockedIpsList();
            updateAlertsList();
        })
        .catch(error => {
            console.error('Error unblocking IP:', error);
            alert('Error unblocking IP: ' + error.message);
        });
    }

    // ------------------------------
    // BLOCKED IP LIST
    // ------------------------------
    function updateBlockedIpsList() {
        fetch('/api/blocked_ips')
            .then(response => response.json())
            .then(data => {
                blockedIpsList.innerHTML = '';
                if (!data.blocked_ips || data.blocked_ips.length === 0) {
                    blockedIpsList.innerHTML = '<p class="text-muted">No IPs are currently blocked.</p>';
                    return;
                }
                const list = document.createElement('ul');
                list.className = 'list-group';
                data.blocked_ips.forEach(ip => {
                    const listItem = document.createElement('li');
                    listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
                    listItem.textContent = ip;
                    const unblockBtn = document.createElement('button');
                    unblockBtn.className = 'btn btn-sm btn-warning';
                    unblockBtn.textContent = 'Unblock';
                    unblockBtn.onclick = () => unblockIp(ip);
                    listItem.appendChild(unblockBtn);
                    list.appendChild(listItem);
                });
                blockedIpsList.appendChild(list);
            })
            .catch(error => {
                console.error('Error fetching blocked IPs:', error);
                blockedIpsList.innerHTML = '<p class="text-danger">Error fetching blocked IPs.</p>';
            });
    }

    // ------------------------------
    // TIME FORMATTER
    // ------------------------------
    function formatTime(seconds) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = Math.floor(seconds % 60);
        return `${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
    }

    // ------------------------------
    // COUNTDOWN TIMER
    // ------------------------------
    function startCountdown(element, remainingTime) {
        let time = remainingTime;
        const ip = element.dataset.ip;

        if (countdownIntervals[ip]) {
            clearInterval(countdownIntervals[ip]);
        }

        const timer = setInterval(() => {
            time--;
            if (time <= 0) {
                clearInterval(timer);
                element.textContent = 'Unblocked';
                updateAlertsList();
            } else {
                element.textContent = formatTime(time);
            }
        }, 1000);

        countdownIntervals[ip] = timer;
    }

    // ------------------------------
    // ALERTS LIST
    // ------------------------------
    function updateAlertsList() {
        fetch('/api/alerts')
            .then(response => response.json())
            .then(data => {
                alertsList.innerHTML = '';

                Object.values(countdownIntervals).forEach(clearInterval);
                countdownIntervals = {};

                if (!data.alerts || data.alerts.length === 0) {
                    alertsList.innerHTML = '<p class="text-muted">No alerts yet.</p>';
                    return;
                }

                const list = document.createElement('ul');
                list.className = 'list-group';

                data.alerts.forEach(alert => {
                    const listItem = document.createElement('li');
                    listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
                    listItem.innerHTML = `
                        <span>${alert.ip}</span>
                        <span class="countdown" data-ip="${alert.ip}">${formatTime(alert.remaining_time)}</span>
                    `;
                    const countdownElement = listItem.querySelector('.countdown');
                    if (alert.remaining_time > 0) {
                        startCountdown(countdownElement, alert.remaining_time);
                    } else {
                        countdownElement.textContent = 'Expired';
                    }
                    list.appendChild(listItem);
                });

                alertsList.appendChild(list);
            })
            .catch(error => {
                console.error('Error fetching alerts:', error);
                alertsList.innerHTML = '<p class="text-danger">Error fetching alerts.</p>';
            });
    }

    // Initial setup
    resultsLog.innerHTML = '<p class="text-muted">Waiting for data from the honeypot simulator...</p>';
    updateBlockedIpsList();
    updateAlertsList();

    // --- Event Listener for Clear All Blocks button ---
    const clearBtn = document.getElementById('clear-blocks-btn');
    if(clearBtn) {
        clearBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to clear all permanent and temporary blocks?')) {
                fetch('/api/clear_all_blocks', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert(data.message);
                        updateBlockedIpsList();
                        updateAlertsList();
                    })
                    .catch(error => {
                        console.error('Error clearing blocks:', error);
                        alert('Error clearing blocks: ' + error.message);
                    });
            }
        });
    }

    // --- Event Listener for Clear Logs button ---
    const clearLogsBtn = document.getElementById('clear-logs-btn');
    if(clearLogsBtn) {
        clearLogsBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to clear all logs?')) {
                fetch('/api/clear_logs', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert(data.message);
                        resultsLog.innerHTML = '<p class="text-muted">Waiting for data from the honeypot simulator...</p>';
                        isFirstPacket = true;
                    })
                    .catch(error => {
                        console.error('Error clearing logs:', error);
                        alert('Error clearing logs: ' + error.message);
                    });
            }
        });
    }


    // --- Event Listener for Generate Summary button ---
    const generateSummaryBtn = document.getElementById('generate-summary-btn');
    const summaryContent = document.getElementById('summary-content');

    if (generateSummaryBtn) {
        generateSummaryBtn.addEventListener('click', function() {
            summaryContent.innerHTML = '<p class="text-muted">Generating summary...</p>';

            fetch(`/api/generate_summary`)
                .then(response => response.json())
                .then(data => {
                    summaryContent.innerHTML = `<p>${data.summary.replace(/\n/g, '<br>')}</p>`;
                })
                .catch(error => {
                    console.error('Error generating summary:', error);
                    summaryContent.innerHTML = '<p class="text-danger">Error generating summary.</p>';
                });
        });
    }
});

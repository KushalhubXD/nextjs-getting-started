// Wait until the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // IP Input functionality
    const ipInput = document.getElementById('ipInput');
    const addNormalBtn = document.getElementById('addNormalBtn');
    const addSynBtn = document.getElementById('addSynBtn');
    const blockIpBtn = document.getElementById('blockIpBtn');
    
    // Filter functionality
    const logFilter = document.getElementById('logFilter');
    const ipFilter = document.getElementById('ipFilter');
    const threatFilter = document.getElementById('threatFilter');
    
    // Initialize the traffic chart
    const ctx = document.getElementById('trafficChart').getContext('2d');
    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Network Traffic',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointRadius: 0,
                pointHoverRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: '#1a1a1a',
                    titleColor: '#ffffff',
                    bodyColor: '#a0a0a0',
                    borderColor: '#2a2a2a',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false,
                        drawBorder: false
                    },
                    ticks: {
                        color: '#a0a0a0'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#2a2a2a',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#a0a0a0'
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });

    // IP validation function
    function isValidIP(ip) {
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!ipRegex.test(ip)) return false;
        
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    // Function to simulate traffic
    function simulateTraffic(ipAddress, eventType) {
        if (!isValidIP(ipAddress)) {
            alert('Please enter a valid IP address');
            return;
        }

        fetch('/simulate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ip_address: ipAddress,
                event: eventType
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'logged') {
                showNotification(`${eventType} event logged for ${ipAddress}`, 'success');
                updateLogs();
                updateThreats();
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error logging event', 'error');
        });
    }

    // Function to show notifications
    function showNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            color: white;
            font-weight: 500;
            z-index: 1000;
            animation: slideIn 0.3s ease;
            background-color: ${type === 'success' ? '#22c55e' : '#ef4444'};
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    // Event listeners for IP input buttons
    if (addNormalBtn) {
        addNormalBtn.addEventListener('click', function() {
            const ip = ipInput.value.trim();
            if (ip) {
                simulateTraffic(ip, 'NORMAL');
                ipInput.value = '';
            }
        });
    }

    if (addSynBtn) {
        addSynBtn.addEventListener('click', function() {
            const ip = ipInput.value.trim();
            if (ip) {
                simulateTraffic(ip, 'SYN');
                ipInput.value = '';
            }
        });
    }

    if (blockIpBtn) {
        blockIpBtn.addEventListener('click', function() {
            const ip = ipInput.value.trim();
            if (ip && isValidIP(ip)) {
                simulateTraffic(ip, 'BLOCKED');
                showNotification(`IP ${ip} has been blocked`, 'success');
                ipInput.value = '';
            }
        });
    }

    // Function to format timestamp
    function formatTime(date) {
        return date.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    // Function to update traffic chart data
    function updateTrafficData() {
        fetch('/api/traffic')
            .then(response => response.json())
            .then(data => {
                trafficChart.data.labels = data.map(point => point.time);
                trafficChart.data.datasets[0].data = data.map(point => point.traffic);
                trafficChart.update('none');
            })
            .catch(error => console.error('Error fetching traffic data:', error));
    }

    // Function to create a status badge
    function createStatusBadge(status) {
        const badge = document.createElement('span');
        badge.className = 'status-badge';
        
        switch(status.toLowerCase()) {
            case 'syn':
                badge.classList.add('status-warning');
                break;
            case 'blocked':
                badge.classList.add('status-danger');
                break;
            case 'normal':
                badge.classList.add('status-ok');
                break;
        }
        
        badge.textContent = status;
        return badge.outerHTML;
    }

    // Function to create action buttons for logs
    function createLogActions(log) {
        return `
            <button class="action-btn-small block" onclick="blockIP('${log.ip_address}')">
                <i class="fas fa-ban"></i>
            </button>
            <button class="action-btn-small details" onclick="showLogDetails('${log.id}')">
                <i class="fas fa-info-circle"></i>
            </button>
        `;
    }

    // Global functions for actions
    window.blockIP = function(ip) {
        if (confirm(`Are you sure you want to block IP ${ip}?`)) {
            simulateTraffic(ip, 'BLOCKED');
        }
    };

    window.showLogDetails = function(logId) {
        showNotification(`Showing details for log ID: ${logId}`, 'success');
    };

    // Function to update logs table with filtering
    function updateLogs() {
        fetch('/api/logs')
            .then(response => response.json())
            .then(data => {
                let filteredData = data;
                
                // Apply filters
                if (logFilter && logFilter.value !== 'all') {
                    filteredData = filteredData.filter(log => log.event === logFilter.value);
                }
                
                if (ipFilter && ipFilter.value.trim()) {
                    const ipFilterValue = ipFilter.value.trim().toLowerCase();
                    filteredData = filteredData.filter(log => 
                        log.ip_address.toLowerCase().includes(ipFilterValue)
                    );
                }
                
                const logsTableBody = document.querySelector('#logsTable tbody');
                logsTableBody.innerHTML = '';
                
                filteredData.forEach(log => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>${log.ip_address}</td>
                        <td>${log.event}</td>
                        <td>${createStatusBadge(log.event)}</td>
                        <td>${createLogActions(log)}</td>
                    `;
                    logsTableBody.appendChild(row);
                });
            })
            .catch(error => console.error('Error fetching logs:', error));
    }

    // Function to update threats table with filtering
    function updateThreats() {
        fetch('/api/threats')
            .then(response => response.json())
            .then(data => {
                let filteredData = data;
                
                // Apply threat filter
                if (threatFilter && threatFilter.value !== 'all') {
                    filteredData = filteredData.filter(threat => threat.alert_type === threatFilter.value);
                }
                
                const alertsTableBody = document.querySelector('#alertsTable tbody');
                alertsTableBody.innerHTML = '';
                
                filteredData.forEach(alert => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(alert.timestamp).toLocaleString()}</td>
                        <td>${alert.ip_address}</td>
                        <td>${alert.alert_type}</td>
                        <td>${createStatusBadge('danger')}</td>
                        <td>
                            <button class="block-btn" onclick="blockIP('${alert.ip_address}')">
                                <i class="fas fa-ban"></i> Block IP
                            </button>
                            <button class="resolve-btn" onclick="resolveThreat('${alert.id}')">
                                <i class="fas fa-check"></i> Resolve
                            </button>
                        </td>
                    `;
                    alertsTableBody.appendChild(row);
                });

                // Update threat counter
                const threatCountElement = document.getElementById('threatCount');
                if (threatCountElement) {
                    threatCountElement.textContent = filteredData.length;
                }
            })
            .catch(error => console.error('Error fetching threats:', error));
    }

    // Global function to resolve threats
    window.resolveThreat = function(threatId) {
        showNotification(`Threat ${threatId} has been resolved`, 'success');
        updateThreats();
    };

    // Add event listeners for filters
    if (logFilter) {
        logFilter.addEventListener('change', updateLogs);
    }
    
    if (ipFilter) {
        ipFilter.addEventListener('input', updateLogs);
    }
    
    if (threatFilter) {
        threatFilter.addEventListener('change', updateThreats);
    }

    // Add click handlers for time control buttons
    document.querySelectorAll('.time-btn').forEach(button => {
        button.addEventListener('click', function() {
            document.querySelectorAll('.time-btn').forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            updateTrafficData();
        });
    });

    // Add click handlers for refresh buttons
    document.querySelectorAll('.refresh-btn').forEach(button => {
        button.addEventListener('click', function() {
            updateLogs();
            updateThreats();
            updateTrafficData();
            showNotification('Data refreshed', 'success');
        });
    });

    // Initial load
    updateTrafficData();
    updateLogs();
    updateThreats();

    // Update every 5 seconds
    setInterval(() => {
        updateTrafficData();
        updateLogs();
        updateThreats();
    }, 5000);
});

// Add enhanced CSS for new features
const style = document.createElement('style');
style.textContent = `
    .status-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.75rem;
        font-weight: 500;
    }
    
    .status-ok {
        background-color: rgba(34, 197, 94, 0.1);
        color: #22c55e;
    }
    
    .status-warning {
        background-color: rgba(234, 179, 8, 0.1);
        color: #eab308;
    }
    
    .status-danger {
        background-color: rgba(239, 68, 68, 0.1);
        color: #ef4444;
    }
    
    .block-btn, .resolve-btn {
        background-color: #ef4444;
        color: white;
        border: none;
        padding: 0.25rem 0.75rem;
        border-radius: 0.375rem;
        cursor: pointer;
        font-size: 0.75rem;
        transition: background-color 0.2s;
        margin-right: 0.5rem;
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
    }
    
    .resolve-btn {
        background-color: #22c55e;
    }
    
    .block-btn:hover {
        background-color: #dc2626;
    }
    
    .resolve-btn:hover {
        background-color: #16a34a;
    }
    
    .action-btn-small {
        background-color: #3b82f6;
        color: white;
        border: none;
        padding: 0.25rem;
        border-radius: 0.25rem;
        cursor: pointer;
        font-size: 0.75rem;
        margin-right: 0.25rem;
        width: 24px;
        height: 24px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
    }
    
    .action-btn-small.block {
        background-color: #ef4444;
    }
    
    .action-btn-small:hover {
        opacity: 0.8;
    }
    
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);

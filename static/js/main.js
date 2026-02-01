// WEBSEC//SCAN - Enterprise Security Analysis System
// Advanced JavaScript Interface v2.0

document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const sampleButton = document.getElementById('sampleButton');
    const resultsPanel = document.getElementById('resultsPanel');
    const consoleOutput = document.getElementById('consoleOutput');
    const errorDisplay = document.getElementById('errorDisplay');
    const loadingOverlay = document.getElementById('loadingOverlay');

    // Status Elements
    const scanStatus = document.getElementById('scanStatus');
    const scanPercent = document.getElementById('scanPercent');
    const resultsStatus = document.getElementById('resultsStatus');

    // Metrics Elements
    const endpointsScanned = document.getElementById('endpointsScanned');
    const requestsMade = document.getElementById('requestsMade');
    const threatsFound = document.getElementById('threatsFound');

    // Results Elements
    const dangerAlert = document.getElementById('dangerAlert');
    const totalVulns = document.getElementById('totalVulns');
    const criticalVulns = document.getElementById('criticalVulns');
    const warningVulns = document.getElementById('warningVulns');
    const infoVulns = document.getElementById('infoVulns');
    const scanTime = document.getElementById('scanTime');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');

    // Solutions DOM
    const solutionsPanel = document.getElementById('solutionsPanel');
    const solutionsGrid = document.getElementById('solutionsGrid');
    const affiliateDisclosure = document.getElementById('affiliateDisclosure');
    const comparisonTable = document.getElementById('comparisonTable');
    const solutionsComparison = document.getElementById('solutionsComparison');

    // Progress Bars
    const totalBar = document.getElementById('totalBar');
    const criticalBar = document.getElementById('criticalBar');
    const warningBar = document.getElementById('warningBar');
    const infoBar = document.getElementById('infoBar');

    // Analytics Consent Elements
    const analyticsConsent = document.getElementById('analyticsConsent');
    const consentAcceptBtn = document.getElementById('consentAcceptBtn');
    const consentDeclineBtn = document.getElementById('consentDeclineBtn');
    const privacyBtn = document.getElementById('privacyBtn');

    // State Variables
    let scanInProgress = false;
    let scanStartTime = 0;
    let currentProgress = 0;
    let scanInterval;
    let consoleLines = 0;
    let lastScanData = null;  // Store last scan data for report generation

    // Initialize System
    initializeSystem();

    function initializeSystem() {
        logToConsole('[INIT] Security scanner initialized...', 'success');
        logToConsole('[STANDBY] Awaiting target input...', 'info');

        // Event Listeners
        if (sampleButton) {
            sampleButton.addEventListener('click', loadSampleTarget);
        }
        if (scanButton) {
            scanButton.addEventListener('click', initiateScan);
        }
        if (urlInput) {
            urlInput.addEventListener('keypress', handleKeyPress);
            urlInput.addEventListener('focus', handleInputFocus);
            urlInput.addEventListener('blur', handleInputBlur);
        }

        // Header Controls
        const settingsBtn = document.getElementById('settingsBtn');
        if (settingsBtn) settingsBtn.addEventListener('click', showSettings);
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) refreshBtn.addEventListener('click', refreshSystem);
        const infoBtn = document.getElementById('infoBtn');
        if (infoBtn) infoBtn.addEventListener('click', showInfo);

        // Footer Controls
        const contactBtn = document.getElementById('contactBtn');
        if (contactBtn) contactBtn.addEventListener('click', showContact);

        // Analytics Consent
        setupAnalyticsConsent();

        // Report Download Buttons
        const downloadReportJsonBtn = document.getElementById('downloadReportJson');
        if (downloadReportJsonBtn) downloadReportJsonBtn.addEventListener('click', downloadReportJson);
        const downloadReportHtmlBtn = document.getElementById('downloadReportHtml');
        if (downloadReportHtmlBtn) downloadReportHtmlBtn.addEventListener('click', downloadReportHtml);
        const downloadReportPdfBtn = document.getElementById('downloadReportPdf');
        if (downloadReportPdfBtn) downloadReportPdfBtn.addEventListener('click', downloadReportPdf);
    }

    function setupAnalyticsConsent() {
        if (privacyBtn) {
            privacyBtn.addEventListener('click', () => {
                if (!analyticsConsent) return;
                const isVisible = analyticsConsent.style.display === 'flex';
                analyticsConsent.style.display = isVisible ? 'none' : 'flex';
            });
        }

        if (consentAcceptBtn) {
            consentAcceptBtn.addEventListener('click', () => handleConsent(true));
        }

        if (consentDeclineBtn) {
            consentDeclineBtn.addEventListener('click', () => handleConsent(false));
        }

        const storedConsent = localStorage.getItem('analytics_consent');
        if (analyticsConsent && storedConsent === null) {
            analyticsConsent.style.display = 'flex';
        }
    }

    function handleConsent(granted) {
        const normalized = granted ? 'true' : 'false';
        localStorage.setItem('analytics_consent', normalized);
        if (window.setAnalyticsConsent) {
            window.setAnalyticsConsent(granted);
        }
        if (analyticsConsent) {
            analyticsConsent.style.display = 'none';
        }
        logToConsole(`[PRIVACY] Analytics ${granted ? 'enabled' : 'disabled'}.`, granted ? 'success' : 'warning');
    }

    function logAnalyticsEvent(eventName, params = {}) {
        if (!window.logFirebaseEvent) return;
        window.logFirebaseEvent(eventName, params);
    }

    function handleKeyPress(e) {
        if (e.key === 'Enter' && !scanInProgress) {
            initiateScan();
        }
    }

    function handleInputFocus() {
        urlInput.parentElement.classList.add('focused');
    }

    function handleInputBlur() {
        urlInput.parentElement.classList.remove('focused');
    }

    function loadSampleTarget() {
        urlInput.value = 'example.com';
        logToConsole('[DEMO] Sample target loaded: example.com', 'info');
        logToConsole('[TIP] Click INITIATE SCAN to begin security analysis', 'success');
        flashElement(urlInput, 'neon-blue');
    }

    function showSettings() {
        logToConsole('[SETTINGS] Opening configuration panel...', 'info');
        // Placeholder for settings modal
        alert('Settings panel - Coming in v2.1');
    }

    function refreshSystem() {
        if (scanInProgress) {
            logToConsole('[ERROR] Cannot refresh during active scan', 'error');
            return;
        }
        logToConsole('[REFRESH] System refresh initiated...', 'info');
        resetInterface();
    }

    function showInfo() {
        logToConsole('[INFO] Displaying system information...', 'info');
        // Placeholder for info modal
        alert('WEBSEC//SCAN v2.0 - Enterprise Security Analysis\nBuilt for professionals by professionals');
    }

    function initiateScan() {
        const url = urlInput.value.trim();
        if (!url) {
            showError('TARGET ACQUISITION FAILED: No URL provided');
            flashElement(urlInput, 'neon-red');
            logToConsole('[ERROR] Please enter a target URL', 'error');
            return;
        }

        if (scanInProgress) {
            logToConsole('[ERROR] Scan already in progress', 'error');
            return;
        }

        // Validate URL format
        if (!isValidUrl(url)) {
            showError('INVALID TARGET: Please enter a valid URL (e.g., example.com or https://example.com)');
            flashElement(urlInput, 'neon-red');
            logToConsole('[ERROR] Invalid URL format provided', 'error');
            return;
        }

        startScan(url);
    }

    function isValidUrl(string) {
        try {
            // Add protocol if missing for validation
            const urlToTest = string.startsWith('http://') || string.startsWith('https://')
                ? string
                : 'http://' + string;
            new URL(urlToTest);
            return true;
        } catch (_) {
            return false;
        }
    }

    function startScan(url) {
        scanInProgress = true;
        scanStartTime = Date.now();
        currentProgress = 0;

        logAnalyticsEvent('scan_started', { source: 'web_ui' });

        // Update UI State
        if (scanButton) {
            scanButton.disabled = true;
            scanButton.textContent = 'SCANNING...';
        }
        if (sampleButton) {
            sampleButton.disabled = true;
        }
        scanStatus.textContent = 'ACTIVE';
        resultsStatus.textContent = 'PROCESSING';

        // Show loading overlay
        loadingOverlay.style.display = 'flex';

        // Reset previous results
        resetResults();

        // Start animations
        startScanAnimation();

        logToConsole(`[INIT] Starting security scan for: ${url}`, 'success');
        logToConsole('[CHECK] Initializing scan protocols...', 'info');

        // Simulate scan progress
        scanInterval = setInterval(updateScanProgress, 200);

        // Make API call
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP Error: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            completeScan(data);
        })
        .catch(error => {
            handleScanError(error.message || 'Unknown error occurred during scan');
        });
    }

    function startScanAnimation() {
        // Animate radar
        const radarRing = document.getElementById('radarRing');
        if (radarRing) {
            radarRing.style.animation = 'radarSweep 1s linear infinite';
        }

        // Start particle effects
        if (scanButton) {
            scanButton.classList.add('scanning');
        }
    }

    function updateScanProgress() {
        if (currentProgress >= 100) return;

        currentProgress += Math.random() * 15;
        if (currentProgress > 100) currentProgress = 100;

        scanPercent.textContent = Math.floor(currentProgress) + '%';

        // Update metrics with fake data
        const endpoints = Math.floor(currentProgress / 10);
        const requests = Math.floor(currentProgress * 2.5);
        const threats = Math.floor(Math.random() * 3);

        endpointsScanned.textContent = endpoints;
        requestsMade.textContent = requests;
        threatsFound.textContent = threats;

        // Add console messages at certain progress points
        if (currentProgress > 20 && currentProgress < 25) {
            logToConsole('[CHECK] Analyzing HTTP headers...', 'info');
        } else if (currentProgress > 40 && currentProgress < 45) {
            logToConsole('[CHECK] Testing endpoint security...', 'info');
        } else if (currentProgress > 60 && currentProgress < 65) {
            logToConsole('[CHECK] Scanning for vulnerabilities...', 'warning');
        } else if (currentProgress > 80 && currentProgress < 85) {
            logToConsole('[CHECK] Generating security report...', 'info');
        }
    }

    function completeScan(data) {
        clearInterval(scanInterval);
        currentProgress = 100;
        if (scanPercent) scanPercent.textContent = '100%';

        // Hide loading overlay
        if (loadingOverlay) loadingOverlay.style.display = 'none';

        // Calculate scan time
        const elapsed = (Date.now() - scanStartTime) / 1000;
        if (scanTime) scanTime.textContent = elapsed.toFixed(2);

        scanInProgress = false;

        if (!data || !data.success) {
            handleScanError((data && (data.error || data.message)) || 'Unknown error occurred during scan');
            return;
        }

        // Update final status
        scanStatus.textContent = 'COMPLETE';
        resultsStatus.textContent = 'ANALYSIS COMPLETE';

        logToConsole(`[COMPLETE] Scan finished in ${elapsed.toFixed(2)} seconds`, 'success');

        // Store scan data for report generation
        lastScanData = data;
        displayResults(data);
        logToConsole('[REPORT] Scan data ready for export', 'success');

        // Reset UI state
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.textContent = 'INITIATE SCAN';
            scanButton.classList.remove('scanning');
        }
        if (sampleButton) {
            sampleButton.disabled = false;
        }
    }

    function handleScanError(message) {
        clearInterval(scanInterval);
        if (loadingOverlay) loadingOverlay.style.display = 'none';
        scanInProgress = false;

        if (scanStatus) scanStatus.textContent = 'ERROR';
        if (resultsStatus) resultsStatus.textContent = 'FAILED';

        if (scanButton) {
            scanButton.disabled = false;
            scanButton.textContent = 'INITIATE SCAN';
            scanButton.classList.remove('scanning');
        }
        if (sampleButton) {
            sampleButton.disabled = false;
        }

        showError(message);
        logToConsole(`[ERROR] ${message}`, 'error');
    }

    function displayResults(data) {
        resultsPanel.style.display = 'block';

        // Update summary stats
        const summary = data.summary || { total: 0, critical: 0, warning: 0, info: 0 };
        totalVulns.textContent = summary.total;
        criticalVulns.textContent = summary.critical;
        warningVulns.textContent = summary.warning;
        infoVulns.textContent = summary.info || 0;

        // Animate progress bars
        setTimeout(() => {
            animateProgressBar(totalBar, summary.total, 10);
            animateProgressBar(criticalBar, summary.critical, summary.total);
            animateProgressBar(warningBar, summary.warning, summary.total);
            animateProgressBar(infoBar, summary.info || 0, summary.total);
        }, 500);

        // Show danger alert if critical vulnerabilities found
        if (summary.critical > 0) {
            dangerAlert.style.display = 'flex';
            logToConsole(`[ALERT] ${summary.critical} critical vulnerabilities detected!`, 'error');
        }

        // Display vulnerabilities
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            displayVulnerabilities(data.vulnerabilities);
        } else {
            logToConsole('[SUCCESS] No vulnerabilities detected - Target appears secure', 'success');
            vulnerabilitiesList.innerHTML = `
                <div class="no-vulns">
                    <svg class="success-icon" aria-hidden="true">
                        <use xlink:href="#icon-check-circle" />
                    </svg>
                    <span>TARGET SECURE - No vulnerabilities found</span>
                </div>
            `;
        }

        // Render recommendations
        // renderSolutions(data.recommendations);
        solutionsPanel.style.display = 'none';
        solutionsComparison.style.display = 'none';

        // Scroll to results
        setTimeout(() => {
            resultsPanel.scrollIntoView({ behavior: 'smooth' });
        }, 1000);
    }

    function renderSolutions(recommendations) {
        if (!recommendations || !recommendations.items || !recommendations.items.length) {
            solutionsPanel.style.display = 'none';
            return;
        }

        solutionsPanel.style.display = 'block';
        affiliateDisclosure.textContent = recommendations.disclosure || 'Affiliate Disclosure: We may earn a commission if you purchase through these links.';

        const cardsHtml = recommendations.items.map(item => `
            <div class="solution-card" data-affiliate="${item.solution_key}">
                <div class="solution-card-header">
                    <div class="solution-name">${item.name}</div>
                    <div class="solution-badges">
                        ${(item.badges || []).map(b => `<span class="badge">${b}</span>`).join('')}
                        ${item.tier === 'free' ? '<span class="badge badge-free">Free</span>' : ''}
                    </div>
                </div>
                <p class="solution-description">${item.description || ''}</p>
                <div class="solution-meta">
                    ${item.commission ? `<span class="meta">Commission: ${item.commission}</span>` : ''}
                    <span class="meta">Priority: ${item.priority}</span>
                </div>
                <div class="solution-actions">
                    <a href="${item.url}" class="btn btn-primary solution-link" data-affiliate-key="${item.solution_key}" data-vuln="${item.vulnerability}" target="_blank" rel="noopener">
                        ${item.cta || 'View Solution'}
                    </a>
                    <button class="btn btn-secondary" data-compare="${item.solution_key}">Compare</button>
                </div>
                <div class="solution-disclosure">Affiliate Link: We may earn a commission if you purchase through this link, at no additional cost to you.</div>
            </div>
        `).join('');

        solutionsGrid.innerHTML = cardsHtml;

        // Click tracking
        solutionsGrid.querySelectorAll('.solution-link').forEach(link => {
            link.addEventListener('click', () => {
                logAffiliateClick({
                    affiliate_key: link.dataset.affiliateKey,
                    vulnerability_type: link.dataset.vuln,
                    target_url: lastScanData?.url,
                    device: navigator.userAgent,
                });
            });
        });

        // Build comparison table (basic)
        if (recommendations.items.length > 1) {
            solutionsComparison.style.display = 'block';
            const rows = recommendations.items.slice(0, 4).map(item => `
                <tr>
                    <td>${item.name}</td>
                    <td>${item.tier || ''}</td>
                    <td>${(item.badges || []).join(', ')}</td>
                    <td>${item.cta || ''}</td>
                </tr>
            `).join('');
            comparisonTable.innerHTML = `
                <table>
                    <thead>
                        <tr><th>Solution</th><th>Tier</th><th>Highlights</th><th>CTA</th></tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            `;
        } else {
            solutionsComparison.style.display = 'none';
        }
    }

    function logAffiliateClick(payload) {
        try {
            fetch('/affiliate-click', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (_) {
            // non-blocking
        }
    }

    function animateProgressBar(bar, value, max) {
        const percentage = max > 0 ? (value / max) * 100 : 0;
        bar.style.width = percentage + '%';
    }

    function displayVulnerabilities(vulnerabilities) {
        vulnerabilitiesList.innerHTML = '';

        vulnerabilities.forEach((vuln, index) => {
            setTimeout(() => {
                const card = createVulnerabilityCard(vuln, index);
                vulnerabilitiesList.appendChild(card);
            }, index * 200);
        });
    }

    function createVulnerabilityCard(vuln, index) {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${getSeverityClass(vuln.severity)}`;
        card.style.animationDelay = `${index * 0.1}s`;

        const severityColor = getSeverityColor(vuln.severity);

        card.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-title">${vuln.type}</div>
                <div class="vuln-severity" style="background: ${severityColor}">${vuln.severity.toUpperCase()}</div>
            </div>
            <div class="vuln-description">${vuln.description}</div>
            <div class="vuln-details" id="details-${index}">
                <strong>IMPACT:</strong> ${vuln.recommendation}<br><br>
                ${Object.keys(vuln.details || {}).length > 0 ?
                    `<strong>TECHNICAL DETAILS:</strong><br><pre>${JSON.stringify(vuln.details, null, 2)}</pre>` :
                    'No additional technical details available.'}
            </div>
            <div class="vuln-actions">
                <button class="vuln-btn" onclick="toggleDetails(${index})">DETAILS</button>
                <button class="vuln-btn" onclick="copyToClipboard('${vuln.type}')">COPY</button>
            </div>
        `;

        return card;
    }

    function getSeverityClass(severity) {
        switch (severity) {
            case 'critical': return 'critical';
            case 'warning': return 'warning';
            case 'info': return 'info';
            default: return '';
        }
    }

    function getSeverityColor(severity) {
        switch (severity) {
            case 'critical': return 'var(--neon-red)';
            case 'warning': return 'var(--neon-yellow)';
            case 'info': return 'var(--neon-blue)';
            default: return 'var(--neon-green)';
        }
    }

    function toggleDetails(index) {
        const details = document.getElementById(`details-${index}`);
        details.classList.toggle('expanded');
    }

    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            logToConsole('[CLIPBOARD] Vulnerability details copied', 'success');
            flashElement(document.body, 'neon-green');
        });
    }

    function logToConsole(message, type = 'info') {
        const line = document.createElement('div');
        line.className = 'console-line';
        line.textContent = message;

        // Color coding
        switch (type) {
            case 'success':
                line.style.color = 'var(--neon-green)';
                break;
            case 'error':
                line.style.color = 'var(--neon-red)';
                break;
            case 'warning':
                line.style.color = 'var(--neon-yellow)';
                break;
            default:
                line.style.color = 'var(--text-secondary)';
        }

        consoleOutput.appendChild(line);
        consoleLines++;

        // Auto-scroll
        consoleOutput.scrollTop = consoleOutput.scrollHeight;

        // Limit console lines
        if (consoleLines > 50) {
            consoleOutput.removeChild(consoleOutput.firstChild);
            consoleLines--;
        }
    }

    function showError(message) {
        const errorMessage = document.getElementById('errorMessage');
        errorMessage.textContent = message;
        errorDisplay.style.display = 'block';

        // Auto-hide after 5 seconds
        setTimeout(() => {
            errorDisplay.style.display = 'none';
        }, 5000);
    }

    function resetResults() {
        resultsPanel.style.display = 'none';
        dangerAlert.style.display = 'none';
        vulnerabilitiesList.innerHTML = '';
        totalVulns.textContent = '0';
        criticalVulns.textContent = '0';
        warningVulns.textContent = '0';
        infoVulns.textContent = '0';
        scanTime.textContent = '0.00';
        currentProgress = 0;
        scanPercent.textContent = '0%';
        endpointsScanned.textContent = '0';
        requestsMade.textContent = '0';
        threatsFound.textContent = '0';

        // Reset progress bars
        [totalBar, criticalBar, warningBar, infoBar].forEach(bar => {
            bar.style.width = '0%';
        });
    }

    function resetInterface() {
        resetResults();
        urlInput.value = '';
        scanStatus.textContent = 'STANDBY';
        resultsStatus.textContent = 'READY';
        consoleOutput.innerHTML = `
            <div class="console-line" style="color: var(--neon-green)">[INIT] Security scanner initialized...</div>
            <div class="console-line" style="color: var(--text-secondary)">[STANDBY] Awaiting target input...</div>
        `;
        consoleLines = 2;
        logToConsole('[REFRESH] System reset complete', 'success');
    }

    function flashElement(element, color) {
        const originalBorder = element.style.borderColor;
        element.style.borderColor = `var(--${color})`;
        element.style.boxShadow = `0 0 20px var(--${color})`;

        setTimeout(() => {
            element.style.borderColor = originalBorder;
            element.style.boxShadow = '';
        }, 500);
    }

    function showContact() {
        logToConsole('[CONTACT] Opening contact information...', 'info');
        const email = 'nourkabbouri022@gmail.com';
        const subject = 'Checkmate Scanner Support Request';
        const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}`;
        
        // Show alert with contact info
        alert(`CONTACT INFORMATION\n\n` +
              `Email: ${email}\n\n` +
              `Click "OK" to open your email client\n` +
              `(If it doesn't open, copy the email address above)`);
        
        // Try to open email client
        window.location.href = mailtoLink;
        logToConsole(`[CONTACT] Contact link: ${email}`, 'success');
    }

    function downloadReportJson() {
        if (!lastScanData) {
            showError('No scan data available. Please complete a scan first.');
            logToConsole('[ERROR] No scan data for report generation', 'error');
            return;
        }

        logToConsole('[REPORT] Generating JSON report...', 'info');
        
        const reportData = {
            generated_at: new Date().toISOString(),
            application: 'Checkmate Vulnerability Scanner',
            version: '1.0.0',
            ...lastScanData
        };

        const dataStr = JSON.stringify(reportData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `vulnerability-report-${lastScanData.url.replace(/[^a-z0-9]/gi, '_')}-${new Date().getTime()}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        logToConsole('[REPORT] JSON report downloaded successfully', 'success');
        flashElement(document.getElementById('downloadReportJson'), 'neon-green');
    }

    function downloadReportHtml() {
        if (!lastScanData) {
            showError('No scan data available. Please complete a scan first.');
            logToConsole('[ERROR] No scan data for report generation', 'error');
            return;
        }

        logToConsole('[REPORT] Generating HTML report...', 'info');

        const htmlContent = generateHtmlReport(lastScanData);
        const htmlBlob = new Blob([htmlContent], { type: 'text/html' });
        const url = URL.createObjectURL(htmlBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `vulnerability-report-${lastScanData.url.replace(/[^a-z0-9]/gi, '_')}-${new Date().getTime()}.html`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        logToConsole('[REPORT] HTML report downloaded successfully', 'success');
        flashElement(document.getElementById('downloadReportHtml'), 'neon-blue');
    }

    function downloadReportPdf() {
        if (!lastScanData) {
            showError('No scan data available. Please complete a scan first.');
            logToConsole('[ERROR] No scan data for report generation', 'error');
            return;
        }

        logToConsole('[REPORT] Generating PDF report...', 'info');
        
        // Create a request to the backend to generate PDF
        fetch('/generate-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(lastScanData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.blob();
        })
        .then(blob => {
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `vulnerability-report-${lastScanData.url.replace(/[^a-z0-9]/gi, '_')}-${new Date().getTime()}.pdf`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            
            logToConsole('[REPORT] PDF report downloaded successfully', 'success');
            flashElement(document.getElementById('downloadReportPdf'), 'neon-red');
        })
        .catch(error => {
            logToConsole(`[ERROR] PDF generation failed: ${error.message}`, 'error');
            showError(`PDF generation failed: ${error.message}`);
        });
    }

    function generateHtmlReport(data) {
        const vulnerabilitiesHtml = (data.vulnerabilities || []).map((vuln, index) => `
            <div class="vulnerability-entry">
                <h4>${vuln.type}</h4>
                <p><strong>Severity:</strong> ${vuln.severity.toUpperCase()}</p>
                <p><strong>Description:</strong> ${vuln.description}</p>
                <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
                <p><strong>Details:</strong> <pre>${JSON.stringify(vuln.details, null, 2)}</pre></p>
            </div>
        `).join('');

        const summary = data.summary || { total: 0, critical: 0, warning: 0, info: 0 };

        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - ${data.url}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        h4 { color: #e74c3c; margin-top: 20px; }
        .summary {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .summary-card {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .summary-card.critical { border-left-color: #e74c3c; }
        .summary-card.warning { border-left-color: #f39c12; }
        .summary-card.info { border-left-color: #3498db; }
        .summary-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        .summary-label {
            font-size: 0.9em;
            color: #7f8c8d;
            margin-top: 5px;
        }
        .meta {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .meta p { margin: 5px 0; }
        .vulnerability-entry {
            border-left: 4px solid #e74c3c;
            padding-left: 15px;
            margin: 20px 0;
            padding-bottom: 15px;
            border-bottom: 1px solid #ecf0f1;
        }
        pre {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            border-top: 1px solid #ecf0f1;
            padding-top: 20px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Vulnerability Report</h1>
        
        <div class="meta">
            <p><strong>Target URL:</strong> ${data.url}</p>
            <p><strong>Scan Time:</strong> ${data.scan_time || 'N/A'} seconds</p>
            <p><strong>Report Generated:</strong> ${new Date().toLocaleString()}</p>
            <p><strong>Scanner:</strong> Checkmate Vulnerability Scanner v1.0.0</p>
        </div>

        <h2>Vulnerability Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <div class="summary-value">${summary.total}</div>
                <div class="summary-label">Total Issues</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-value">${summary.critical}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card warning">
                <div class="summary-value">${summary.warning}</div>
                <div class="summary-label">Warnings</div>
            </div>
            <div class="summary-card info">
                <div class="summary-value">${summary.info || 0}</div>
                <div class="summary-label">Info</div>
            </div>
        </div>

        <h2>Detailed Findings</h2>
        ${vulnerabilitiesHtml || '<p>No vulnerabilities found.</p>'}

        <div class="footer">
            <p>This report was automatically generated by Checkmate Vulnerability Scanner</p>
            <p>For more information and support, visit: nourkabbouri022@gmail.com</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    // Global functions for HTML onclick
    window.toggleDetails = toggleDetails;
    window.copyToClipboard = copyToClipboard;
});
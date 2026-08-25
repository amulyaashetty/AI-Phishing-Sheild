/**
 * Analyzer Page JavaScript
 * Handles email analysis form submission and result display
 */

document.addEventListener('DOMContentLoaded', function() {
    const analyzeForm = document.getElementById('analyzeForm');
    
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', handleAnalyze);
    }
    
    // Setup button actions
    setupResultActions();
});

/**
 * Handle form submission for email analysis
 */
async function handleAnalyze(event) {
    event.preventDefault();
    
    hideError();
    
    // Get input data
    const emailText = document.getElementById('emailText').value.trim();
    const emailFile = document.getElementById('emailFile').files[0];
    
    // Validate input
    if (!emailText && !emailFile) {
        showError('Please provide email content via text or file upload.');
        return;
    }
    
    // Show loading
    showLoading('loadingIndicator');
    document.getElementById('resultsSection').classList.add('hidden');
    
    try {
        // Prepare form data
        const formData = new FormData();
        
        if (emailText) {
            formData.append('email_text', emailText);
        }
        
        if (emailFile) {
            formData.append('email_file', emailFile);
        }
        
        // Make API call
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Analysis failed');
        }
        
        // Display results
        displayResults(data.analysis);
        
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading('loadingIndicator');
    }
}

/**
 * Display analysis results
 */
function displayResults(analysis) {
    // Update risk score circle
    const scoreCircle = document.querySelector('.score-circle');
    const riskScore = document.getElementById('riskScore');
    const riskLevel = document.getElementById('riskLevel');
    
    scoreCircle.textContent = `${Math.round(analysis.risk_score)}%`;
    riskScore.textContent = `${analysis.risk_score}%`;
    riskLevel.textContent = analysis.risk_level;
    
    // Update risk card styling
    const riskCard = document.getElementById('riskCard');
    riskCard.className = `result-card risk-card ${getRiskLevelClass(analysis.risk_level)}`;
    
    // Add badge
    const badge = getRiskBadge(analysis.risk_level);
    riskCard.querySelector('h2').textContent = `${badge} Risk Assessment: ${analysis.risk_level}`;
    
    // Display indicators
    const indicatorsList = document.getElementById('indicatorsList');
    indicatorsList.innerHTML = '';
    
    analysis.detected_indicators.forEach(indicator => {
        const li = document.createElement('li');
        li.textContent = indicator;
        indicatorsList.appendChild(li);
    });
    
    // Display AI explanation
    document.getElementById('aiExplanation').textContent = analysis.ai_explanation;
    
    // Display email details
    const details = analysis.email_details;
    document.getElementById('detailSender').textContent = details.sender || 'Unknown';
    document.getElementById('detailSubject').textContent = details.subject || 'No subject';
    document.getElementById('detailLinks').textContent = details.links_found || 0;
    document.getElementById('detailEmails').textContent = details.emails_found || 0;
    
    // Display recommendations
    const recommendationsList = document.getElementById('recommendationsList');
    recommendationsList.innerHTML = '';
    
    analysis.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.innerHTML = rec;
        recommendationsList.appendChild(li);
    });
    
    // Show results section
    document.getElementById('resultsSection').classList.remove('hidden');
    
    // Scroll to results
    setTimeout(() => {
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
    }, 100);
}

/**
 * Setup result action buttons
 */
function setupResultActions() {
    const analyzeAnotherBtn = document.getElementById('analyzeAnotherBtn');
    const viewHistoryBtn = document.getElementById('viewHistoryBtn');
    
    if (analyzeAnotherBtn) {
        analyzeAnotherBtn.addEventListener('click', resetAnalyzer);
    }
    
    if (viewHistoryBtn) {
        viewHistoryBtn.addEventListener('click', function() {
            window.location.href = '/history';
        });
    }
}

/**
 * Load sample email for testing
 */
function loadSampleEmail() {
    const sampleEmail = `From: support@banksecurity.com
To: customer@example.com
Subject: URGENT: Verify Your Account Now

Dear Customer,

We detected suspicious activity on your bank account. 
Your access has been temporarily suspended for security.

CLICK HERE to verify your identity immediately:
http://bit.ly/verify-bank-account

If you don't verify within 24 hours, your account will be permanently closed.

Your banking information is at risk.

Click the link below:
<a href="http://192.168.1.50/fake-login">Verify Account</a>

- Bank Security Team
support@banksecurity.com`;
    
    document.getElementById('emailText').value = sampleEmail;
    
    // Switch to paste tab
    document.querySelector('[data-tab="paste"]').click();
    
    // Close modal if open
    closeModal('sampleModal');
}

/**
 * Close sample modal
 */
function closeSampleModal() {
    closeModal('sampleModal');
}


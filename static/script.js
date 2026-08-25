/**
 * Main JavaScript - AI Phishing Shield
 * Handles common interactions across all pages
 */

// ===== Utility Functions =====

/**
 * Show a loading spinner
 */
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.remove('hidden');
    }
}

/**
 * Hide a loading spinner
 */
function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.add('hidden');
    }
}

/**
 * Show error message
 */
function showError(message, elementId = 'errorSection') {
    const errorSection = document.getElementById(elementId);
    const errorMessage = document.getElementById('errorMessage');
    
    if (errorMessage) {
        errorMessage.textContent = message;
    }
    
    if (errorSection) {
        errorSection.classList.remove('hidden');
    }
}

/**
 * Hide error message
 */
function hideError(elementId = 'errorSection') {
    const errorSection = document.getElementById(elementId);
    if (errorSection) {
        errorSection.classList.add('hidden');
    }
}

/**
 * Format date to readable string
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

/**
 * Get CSS class for risk level
 */
function getRiskLevelClass(riskLevel) {
    const classMap = {
        'Low': 'risk-low',
        'Moderate': 'risk-moderate',
        'High': 'risk-high',
        'Critical': 'risk-critical'
    };
    return classMap[riskLevel] || 'risk-moderate';
}

/**
 * Get risk badge emoji
 */
function getRiskBadge(riskLevel) {
    const badges = {
        'Low': '✅',
        'Moderate': '⚠️',
        'High': '❌',
        'Critical': '🚨'
    };
    return badges[riskLevel] || '❓';
}

/**
 * API call wrapper with error handling
 */
async function apiCall(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Setup tab navigation
 */
function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            
            // Remove active class from all buttons
            tabButtons.forEach(btn => btn.classList.remove('active'));
            
            // Remove active class from all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Add active class to corresponding tab content
            const tabContent = document.getElementById(`${tabName}-tab`);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        });
    });
}

/**
 * Setup file input handler
 */
function setupFileInput() {
    const fileInput = document.getElementById('emailFile');
    
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                const fileName = this.files[0].name;
                console.log('File selected:', fileName);
            }
        });
    }
}

/**
 * Clear form and reset state
 */
function resetAnalyzer() {
    const form = document.getElementById('analyzeForm');
    if (form) {
        form.reset();
    }
    
    hideError();
    document.getElementById('resultsSection').classList.add('hidden');
}

// ===== Initialization =====

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    setupTabs();
    setupFileInput();
    
    // Setup any close buttons
    const closeButtons = document.querySelectorAll('.close-btn');
    closeButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            // This will be overridden by specific pages
        });
    });
});

// ===== Modal Functions =====

/**
 * Close modal dialog
 */
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
    }
}

/**
 * Open modal dialog
 */
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('hidden');
    }
}

/**
 * Close modal when clicking outside
 */
document.addEventListener('click', function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.classList.add('hidden');
    }
});


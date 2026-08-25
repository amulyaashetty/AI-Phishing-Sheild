/**
 * History Page JavaScript
 * Loads and displays analysis history
 */

document.addEventListener('DOMContentLoaded', function() {
    loadHistory();
    setupFilters();
});

/**
 * Load analysis history from API
 */
async function loadHistory() {
    try {
        const response = await apiCall('/api/history');
        
        if (response.success) {
            displayHistory(response.analyses);
            updateStatistics(response.stats);
        }
    } catch (error) {
        console.error('Error loading history:', error);
        showHistoryError('Failed to load history');
    }
}

/**
 * Display history in table
 */
function displayHistory(analyses) {
    const tbody = document.getElementById('historyTableBody');
    const noResults = document.getElementById('noResultsMessage');
    
    if (!analyses || analyses.length === 0) {
        tbody.innerHTML = '';
        noResults.classList.remove('hidden');
        return;
    }
    
    noResults.classList.add('hidden');
    tbody.innerHTML = '';
    
    analyses.forEach(analysis => {
        const row = document.createElement('tr');
        const date = new Date(analysis.created_at);
        const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        const badge = getRiskBadge(analysis.risk_level);
        
        row.innerHTML = `
            <td>${formattedDate}</td>
            <td>${analysis.analysis_type}</td>
            <td>${Math.round(analysis.risk_score)}%</td>
            <td>
                <span class="${getRiskLevelClass(analysis.risk_level)}">
                    ${badge} ${analysis.risk_level}
                </span>
            </td>
            <td>${truncateText(analysis.input_content, 50)}</td>
            <td>
                <button class="btn btn-small" onclick="viewDetail(${analysis.id})">
                    View
                </button>
                <button class="btn btn-small btn-danger" onclick="deleteAnalysis(${analysis.id})">
                    Delete
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

/**
 * Update statistics display
 */
function updateStatistics(stats) {
    document.getElementById('totalAnalyses').textContent = stats.total_analyses;
    document.getElementById('avgRiskScore').textContent = 
        Math.round(stats.average_risk_score) + '%';
    
    document.getElementById('criticalCount').textContent = 
        stats.risk_distribution['Critical'] || 0;
    document.getElementById('highCount').textContent = 
        stats.risk_distribution['High'] || 0;
}

/**
 * View detailed analysis
 */
async function viewDetail(analysisId) {
    try {
        const response = await apiCall(`/api/analysis/${analysisId}`);
        
        if (response.success) {
            displayDetailModal(response.analysis);
            openModal('detailModal');
        }
    } catch (error) {
        console.error('Error loading detail:', error);
        alert('Failed to load analysis details');
    }
}

/**
 * Display detail in modal
 */
function displayDetailModal(analysis) {
    const detailContent = document.getElementById('detailContent');
    const date = new Date(analysis.created_at);
    const badge = getRiskBadge(analysis.risk_level);
    
    let indicatorsHtml = analysis.detected_indicators
        .map(ind => `<li>${ind}</li>`)
        .join('');
    
    let recommendationsHtml = analysis.recommendations
        .map(rec => `<li>${rec}</li>`)
        .join('');
    
    detailContent.innerHTML = `
        <h2>${badge} Analysis Detail - ${analysis.risk_level}</h2>
        
        <div class="detail-section">
            <h3>Analysis Information</h3>
            <table>
                <tr>
                    <td><strong>Date:</strong></td>
                    <td>${date.toLocaleDateString()} ${date.toLocaleTimeString()}</td>
                </tr>
                <tr>
                    <td><strong>Type:</strong></td>
                    <td>${analysis.analysis_type}</td>
                </tr>
                <tr>
                    <td><strong>Risk Score:</strong></td>
                    <td class="${getRiskLevelClass(analysis.risk_level)}">
                        ${analysis.risk_score}%
                    </td>
                </tr>
            </table>
        </div>
        
        <div class="detail-section">
            <h3>Detected Indicators</h3>
            <ul>${indicatorsHtml}</ul>
        </div>
        
        <div class="detail-section">
            <h3>AI Analysis</h3>
            <p>${analysis.ai_explanation}</p>
        </div>
        
        <div class="detail-section">
            <h3>Recommendations</h3>
            <ol>${recommendationsHtml}</ol>
        </div>
        
        <div class="detail-section">
            <h3>Email Content (First 500 chars)</h3>
            <pre>${escapeHtml(analysis.input_content.substring(0, 500))}</pre>
        </div>
    `;
}

/**
 * Delete analysis
 */
async function deleteAnalysis(analysisId) {
    if (!confirm('Are you sure you want to delete this analysis?')) {
        return;
    }
    
    try {
        const response = await apiCall(`/api/analysis/${analysisId}/delete`, {
            method: 'POST'
        });
        
        if (response.success) {
            alert('Analysis deleted successfully');
            loadHistory();
        }
    } catch (error) {
        console.error('Error deleting analysis:', error);
        alert('Failed to delete analysis');
    }
}

/**
 * Setup search and filter functionality
 */
function setupFilters() {
    const searchInput = document.getElementById('searchInput');
    const riskLevelFilter = document.getElementById('riskLevelFilter');
    
    if (searchInput) {
        searchInput.addEventListener('input', applyFilters);
    }
    
    if (riskLevelFilter) {
        riskLevelFilter.addEventListener('change', applyFilters);
    }
}

/**
 * Apply search and filter
 */
function applyFilters() {
    const searchInput = document.getElementById('searchInput').value.toLowerCase();
    const riskFilter = document.getElementById('riskLevelFilter').value;
    
    const rows = document.querySelectorAll('#historyTableBody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const riskLevel = row.cells[3].textContent;
        
        const matchesSearch = text.includes(searchInput);
        const matchesRisk = !riskFilter || riskLevel.includes(riskFilter);
        
        row.style.display = (matchesSearch && matchesRisk) ? '' : 'none';
    });
}

/**
 * Truncate text
 */
function truncateText(text, length) {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Close detail modal
 */
function closeDetailModal() {
    closeModal('detailModal');
}

/**
 * Show error message
 */
function showHistoryError(message) {
    const tbody = document.getElementById('historyTableBody');
    tbody.innerHTML = `<tr><td colspan="6" class="text-center error">${message}</td></tr>`;
}


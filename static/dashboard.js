/**
 * Dashboard Page JavaScript
 * Loads dashboard data and renders charts
 */

let riskChart = null;

document.addEventListener('DOMContentLoaded', function() {
    loadDashboardData();
});

/**
 * Load dashboard data from API
 */
async function loadDashboardData() {
    try {
        const response = await apiCall('/api/history');
        
        if (response.success) {
            updateMetrics(response.stats);
            updateRecentAnalyses(response.analyses);
            renderRiskChart(response.stats.risk_distribution);
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

/**
 * Update key metrics
 */
function updateMetrics(stats) {
    document.getElementById('metricTotal').textContent = stats.total_analyses;
    document.getElementById('metricAvgRisk').textContent = 
        Math.round(stats.average_risk_score) + '%';
    document.getElementById('metricCritical').textContent = 
        stats.risk_distribution['Critical'] || 0;
    document.getElementById('metricHigh').textContent = 
        stats.risk_distribution['High'] || 0;
}

/**
 * Update recent analyses table
 */
function updateRecentAnalyses(analyses) {
    const tbody = document.getElementById('recentAnalysesBody');
    tbody.innerHTML = '';
    
    if (!analyses || analyses.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4">No analyses yet</td></tr>';
        return;
    }
    
    analyses.slice(0, 10).forEach(analysis => {
        const date = new Date(analysis.created_at);
        const badge = getRiskBadge(analysis.risk_level);
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${date.toLocaleDateString()} ${date.toLocaleTimeString()}</td>
            <td>
                <span class="${getRiskLevelClass(analysis.risk_level)}">
                    ${badge} ${analysis.risk_level}
                </span>
            </td>
            <td>${Math.round(analysis.risk_score)}%</td>
            <td>
                <button class="btn btn-small" onclick="window.location.href='/history'">
                    View Details
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

/**
 * Render risk distribution chart
 */
function renderRiskChart(riskDistribution) {
    const ctx = document.getElementById('riskChart');
    
    if (!ctx) return;
    
    // Prepare data
    const levels = ['Low', 'Moderate', 'High', 'Critical'];
    const data = levels.map(level => riskDistribution[level] || 0);
    const colors = ['#16a34a', '#f59e0b', '#dc2626', '#b91c1c'];
    
    // Destroy existing chart if it exists
    if (riskChart) {
        riskChart.destroy();
    }
    
    // Create new chart
    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: levels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: '#fff',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.label + ': ' + context.parsed + ' emails';
                        }
                    }
                }
            }
        }
    });
}

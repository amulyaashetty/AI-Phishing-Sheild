"""
Main Flask Application
Entry point for the AI Phishing Shield web application.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Import our modules
from database.db_manager import DatabaseManager
from models.detection_engine import PhishingDetectionEngine

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'eml'}

# Initialize database
db = DatabaseManager()

# Initialize detection engine
detection_engine = PhishingDetectionEngine()


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Home page - main entry point."""
    return render_template('index.html')


@app.route('/analyzer')
def analyzer():
    """Phishing analyzer page."""
    return render_template('analyzer.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    API endpoint for analyzing email content.
    Accepts JSON with email_content or form data.
    """
    try:
        email_content = None
        
        # Try JSON first
        if request.is_json:
            data = request.get_json()
            email_content = data.get('email_content', '').strip() if data else None
        
        # Fall back to form data
        if not email_content:
            if 'email_text' in request.form and request.form['email_text'].strip():
                email_content = request.form['email_text']
            elif 'email_file' in request.files:
                file = request.files['email_file']
                if file and file.filename and allowed_file(file.filename):
                    email_content = file.read().decode('utf-8', errors='ignore')
                else:
                    return jsonify({'error': 'Invalid file format. Please upload .txt or .eml files'}), 400
        
        # Validate email content
        if not email_content or not email_content.strip():
            return jsonify({'error': 'Please provide email content'}), 400
        
        # Run analysis
        analysis_result = detection_engine.analyze_email(email_content)
        
        # Save to database
        analysis_id = db.save_analysis(analysis_result)
        
        scores = analysis_result.get('scores', {})
        breakdown = analysis_result.get('breakdown', {})
        confidence_info = analysis_result.get('detection_confidence', {})
        keywords_found = breakdown.get('keywords_found', {}) or {}
        sender_rep = breakdown.get('sender_reputation', {}) or {}
        attachments = breakdown.get('attachments', {}) or {}

        # Max possible value for each detector, used to compute % flagged bars
        detector_max = {
            'keyword_score': 30,
            'url_score': 25,
            'regex_score': 100,
            'sender_score': 20,
            'attachment_score': 15,
            'ai_score': 100
        }

        def build_detector_row(key, label):
            score = scores.get(key, 0) or 0
            max_val = detector_max[key]
            flagged = score / max_val >= 0.5 if max_val else False
            return {
                'label': label,
                'score': round(score, 1),
                'max': max_val,
                'flagged': flagged,
                'description': build_description(key)
            }

        def build_description(key):
            if key == 'keyword_score':
                parts = []
                if keywords_found.get('urgent'):
                    parts.append('urgent action keywords')
                if keywords_found.get('credentials'):
                    parts.append('credential requests')
                if keywords_found.get('fear_tactics'):
                    parts.append('fear tactics')
                return ' + '.join(parts).capitalize() if parts else 'No suspicious keywords detected'
            if key == 'url_score':
                suspicious = breakdown.get('suspicious_urls', 0)
                return f'{suspicious} suspicious URL(s) detected' if suspicious else 'No suspicious URLs detected'
            if key == 'regex_score':
                return 'Suspicious regex patterns detected' if scores.get('regex_score', 0) > 0 else 'No suspicious patterns detected'
            if key == 'sender_score':
                if sender_rep.get('is_free_email'):
                    return 'Free email service, not a verified domain'
                return 'Sender domain reputation checked'
            if key == 'attachment_score':
                if attachments.get('has_critical'):
                    return 'Dangerous attachments detected'
                if attachments.get('has_macros'):
                    return 'Macro-enabled attachments detected'
                return 'No dangerous attachments detected'
            if key == 'ai_score':
                return 'AI model flagged this email as risky' if scores.get('ai_score', 0) > 50 else 'AI model found low risk indicators'
            return ''

        # Format response for frontend
        response = {
            'id': analysis_id,
            'risk_score': analysis_result.get('risk_score', 0),
            'risk_level': analysis_result.get('risk_level', 'Unknown'),
            'risk_summary': analysis_result.get('analysis_type', 'Email analysis'),
            'confidence': confidence_info.get('consensus', 'Moderate'),
            'confidence_percentage': round(confidence_info.get('confidence_percentage', 0)),
            'detectors_flagged': confidence_info.get('detectors_flagged', 0),
            'total_detectors': confidence_info.get('total_detectors', 0),
            'concerns': [],
            'ai_explanation': analysis_result.get('ai_explanation', ''),
            'recommendation': analysis_result.get('recommendations', ['Take appropriate action'])[0] if analysis_result.get('recommendations') else 'Review carefully',
            'scores': {
                'keyword_score': scores.get('keyword_score', 0),
                'url_score': scores.get('url_score', 0),
                'regex_score': scores.get('regex_score', 0),
                'sender_score': scores.get('sender_score', 0),
                'attachment_score': scores.get('attachment_score', 0),
                'ai_score': scores.get('ai_score', 0)
            },
            'detectors': {
                'keyword': build_detector_row('keyword_score', 'Keyword'),
                'url': build_detector_row('url_score', 'URL'),
                'regex': build_detector_row('regex_score', 'Regex'),
                'sender': build_detector_row('sender_score', 'Sender'),
                'attachment': build_detector_row('attachment_score', 'Attachment')
            }
        }
        
        # Build concerns list from indicators
        if analysis_result.get('detected_indicators'):
            for idx, indicator in enumerate(analysis_result['detected_indicators'][:4]):
                severity = 'high' if 'CRITICAL' in indicator or '🚨' in indicator else 'medium'
                response['concerns'].append({
                    'title': indicator.split('(')[0].strip() if '(' in indicator else indicator,
                    'description': indicator,
                    'severity': severity
                })
        
        return jsonify(response), 200
    
    except Exception as e:
        print(f"Error in analysis: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/history')
def history():
    """Display analysis history."""
    return render_template('history.html')


@app.route('/api/analyses', methods=['GET'])
def api_analyses():
    """API endpoint to get analysis history."""
    try:
        limit = request.args.get('limit', 100, type=int)
        analyses = db.get_all_analyses(limit=limit)
        
        # Convert to frontend format
        formatted = []
        for a in analyses:
            formatted.append({
                'id': a.get('id'),
                'timestamp': a.get('created_at'),
                'sender': a.get('sender', 'Unknown'),
                'subject': a.get('subject', '(no subject)'),
                'risk_score': a.get('risk_score', 0),
                'risk_level': a.get('risk_level', 'Unknown')
            })
        
        return jsonify(formatted), 200
    
    except Exception as e:
        print(f"Error fetching analyses: {str(e)}")
        return jsonify([]), 200


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """API endpoint to get dashboard statistics."""
    try:
        stats = db.get_statistics()
        analyses = db.get_all_analyses(limit=1000)
        
        # Calculate stats
        total = len(analyses) if analyses else 0
        high_risk = sum(1 for a in (analyses or []) if a.get('risk_level') in ['High', 'Critical'])
        safe = sum(1 for a in (analyses or []) if a.get('risk_level') == 'Low')
        avg_risk = sum(a.get('risk_score', 0) for a in (analyses or [])) / total if total > 0 else 0
        detection_rate = int((high_risk / total * 100)) if total > 0 else 0
        
        return jsonify({
            'total': total,
            'detection_rate': detection_rate,
            'high_risk': high_risk,
            'safe': safe,
            'avg_risk': round(avg_risk)
        }), 200
    
    except Exception as e:
        print(f"Error calculating stats: {str(e)}")
        return jsonify({
            'total': 0,
            'detection_rate': 0,
            'high_risk': 0,
            'safe': 0,
            'avg_risk': 0
        }), 200


@app.route('/api/analysis/<int:analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Get detailed analysis by ID."""
    try:
        analysis = db.get_analysis_by_id(analysis_id)
        
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        
        return jsonify({
            'success': True,
            'analysis': analysis
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/<int:analysis_id>/delete', methods=['POST'])
def delete_analysis(analysis_id):
    """Delete an analysis record."""
    try:
        success = db.delete_analysis(analysis_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Analysis deleted'}), 200
        else:
            return jsonify({'error': 'Analysis not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dashboard')
def dashboard():
    """Dashboard with statistics."""
    stats = db.get_statistics()
    analyses = db.get_all_analyses(limit=10)
    
    return render_template('dashboard.html', stats=stats, recent_analyses=analyses)


@app.route('/about')
def about():
    """About page - project information."""
    return render_template('about.html')


@app.route('/education')
def education():
    """Educational resources page."""
    return render_template('education.html')


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors."""
    return render_template('500.html'), 500


if __name__ == '__main__':
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Run the Flask application
    # Debug=True for development, set to False for production
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000
    )

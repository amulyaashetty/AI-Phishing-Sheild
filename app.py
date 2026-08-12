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
def home():
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
    Accepts email content via text input or file upload.
    """
    try:
        email_content = None
        
        # Check for text input
        if 'email_text' in request.form and request.form['email_text'].strip():
            email_content = request.form['email_text']
        
        # Check for file upload
        elif 'email_file' in request.files:
            file = request.files['email_file']
            
            if file and file.filename and allowed_file(file.filename):
                # Read file content
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
        analysis_result['id'] = analysis_id
        
        return jsonify({
            'success': True,
            'analysis': analysis_result
        }), 200
    
    except Exception as e:
        print(f"Error in analysis: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/history')
def history():
    """Display analysis history."""
    analyses = db.get_all_analyses(limit=50)
    stats = db.get_statistics()
    return render_template('history.html', analyses=analyses, stats=stats)


@app.route('/api/history', methods=['GET'])
def api_history():
    """API endpoint to get analysis history."""
    try:
        limit = request.args.get('limit', 50, type=int)
        analyses = db.get_all_analyses(limit=limit)
        stats = db.get_statistics()
        
        return jsonify({
            'success': True,
            'analyses': analyses,
            'stats': stats
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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

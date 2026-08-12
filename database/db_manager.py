"""
Database Manager Module
Handles all database operations for AI Phishing Shield.
This module manages SQLite database for storing analysis history.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path


class DatabaseManager:
    """
    Manages all database operations for the phishing shield application.
    Creates tables, inserts records, and retrieves analysis history.
    """
    
    def __init__(self, db_path="database/phishing.db"):
        """
        Initialize the database manager.
        
        Args:
            db_path (str): Path to the SQLite database file
        """
        self.db_path = db_path
        # Create database directory if it doesn't exist
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Create database tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table for storing phishing analysis
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phishing_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_type TEXT NOT NULL,
                input_content TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                detected_indicators TEXT NOT NULL,
                ai_explanation TEXT NOT NULL,
                recommendations TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_analysis(self, analysis_data):
        """
        Save analysis result to database.
        
        Args:
            analysis_data (dict): Dictionary containing analysis results
                - analysis_type: 'email', 'url', 'sms', 'website'
                - input_content: The text/content analyzed
                - risk_score: Float between 0-100
                - risk_level: 'Low', 'Moderate', 'High', 'Critical'
                - detected_indicators: List of suspicious indicators
                - ai_explanation: AI's reasoning
                - recommendations: List of recommendations
        
        Returns:
            int: ID of inserted record
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Convert lists to JSON strings for storage
        indicators_json = json.dumps(analysis_data.get('detected_indicators', []))
        recommendations_json = json.dumps(analysis_data.get('recommendations', []))
        
        cursor.execute('''
            INSERT INTO phishing_analysis 
            (analysis_type, input_content, risk_score, risk_level, 
             detected_indicators, ai_explanation, recommendations)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_data.get('analysis_type', 'email'),
            analysis_data.get('input_content', ''),
            analysis_data.get('risk_score', 0),
            analysis_data.get('risk_level', 'Unknown'),
            indicators_json,
            analysis_data.get('ai_explanation', ''),
            recommendations_json
        ))
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        
        return record_id
    
    def get_all_analyses(self, limit=50):
        """
        Retrieve all analysis history.
        
        Args:
            limit (int): Maximum number of records to retrieve
        
        Returns:
            list: List of analysis records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, analysis_type, risk_score, risk_level, 
                   created_at, input_content
            FROM phishing_analysis
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        # Convert results to list of dictionaries
        analyses = []
        for row in results:
            analyses.append({
                'id': row[0],
                'analysis_type': row[1],
                'risk_score': row[2],
                'risk_level': row[3],
                'created_at': row[4],
                'input_content': row[5][:100]  # First 100 chars for preview
            })
        
        return analyses
    
    def get_analysis_by_id(self, analysis_id):
        """
        Retrieve a specific analysis by ID.
        
        Args:
            analysis_id (int): ID of the analysis record
        
        Returns:
            dict: Analysis record with all details
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, analysis_type, input_content, risk_score, 
                   risk_level, detected_indicators, ai_explanation, 
                   recommendations, created_at
            FROM phishing_analysis
            WHERE id = ?
        ''', (analysis_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        return {
            'id': result[0],
            'analysis_type': result[1],
            'input_content': result[2],
            'risk_score': result[3],
            'risk_level': result[4],
            'detected_indicators': json.loads(result[5]),
            'ai_explanation': result[6],
            'recommendations': json.loads(result[7]),
            'created_at': result[8]
        }
    
    def get_statistics(self):
        """
        Get statistics about all analyses.
        
        Returns:
            dict: Statistics including total analyses, risk distribution
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total analyses
        cursor.execute('SELECT COUNT(*) FROM phishing_analysis')
        total = cursor.fetchone()[0]
        
        # Risk level distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) 
            FROM phishing_analysis 
            GROUP BY risk_level
        ''')
        risk_distribution = dict(cursor.fetchall())
        
        # Average risk score
        cursor.execute('SELECT AVG(risk_score) FROM phishing_analysis')
        avg_risk = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_analyses': total,
            'risk_distribution': risk_distribution,
            'average_risk_score': round(avg_risk, 2)
        }
    
    def delete_analysis(self, analysis_id):
        """
        Delete an analysis record.
        
        Args:
            analysis_id (int): ID of the analysis to delete
        
        Returns:
            bool: True if deletion was successful
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM phishing_analysis WHERE id = ?', (analysis_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success

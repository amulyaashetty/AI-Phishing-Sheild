"""
Risk Calculator Module
Combines all detection results into a unified risk score.
"""


class RiskCalculator:
    """
    Calculates final risk scores and levels from all detectors.
    This is where all the pieces come together.
    """
    
    # Risk thresholds
    RISK_THRESHOLDS = {
        'Low': (0, 30),
        'Moderate': (30, 60),
        'High': (60, 80),
        'Critical': (80, 100)
    }
    
    # Detection weights
    WEIGHTS = {
        'keyword_detection': 0.15,      # 15%
        'url_detection': 0.12,          # 12%
        'regex_detection': 0.15,        # 15%
        'sender_detection': 0.08,       # 8%
        'attachment_detection': 0.10,   # 10%
        'ai_analysis': 0.40             # 40%
    }
    
    def __init__(self):
        """Initialize calculator."""
        pass
    
    def calculate_combined_score(self, scores_dict):
        """
        Calculate weighted combined risk score.
        
        Args:
            scores_dict (dict): Dictionary with detection scores:
                {
                    'keyword_score': float (0-30),
                    'url_score': float (0-25),
                    'regex_score': float (0-100),
                    'sender_score': float (0-20),
                    'attachment_score': float (0-15),
                    'ai_score': float (0-100)
                }
        
        Returns:
            float: Combined risk score (0-100)
        """
        # Normalize scores to 0-100 range
        keyword_normalized = min(scores_dict.get('keyword_score', 0) * 3.33, 100)
        url_normalized = min(scores_dict.get('url_score', 0) * 4, 100)
        regex_normalized = scores_dict.get('regex_score', 0)
        sender_normalized = min(scores_dict.get('sender_score', 0) * 5, 100)
        attachment_normalized = min(scores_dict.get('attachment_score', 0) * 6.67, 100)
        ai_normalized = scores_dict.get('ai_score', 0)
        
        # Apply weights
        combined = (
            keyword_normalized * self.WEIGHTS['keyword_detection'] +
            url_normalized * self.WEIGHTS['url_detection'] +
            regex_normalized * self.WEIGHTS['regex_detection'] +
            sender_normalized * self.WEIGHTS['sender_detection'] +
            attachment_normalized * self.WEIGHTS['attachment_detection'] +
            ai_normalized * self.WEIGHTS['ai_analysis']
        )
        
        # Cap at 100
        return min(combined, 100)
    
    def score_to_risk_level(self, score):
        """
        Convert numerical score to risk level.
        
        Args:
            score (float): Risk score 0-100
        
        Returns:
            str: Risk level (Low, Moderate, High, Critical)
        """
        for level, (min_score, max_score) in self.RISK_THRESHOLDS.items():
            if min_score <= score < max_score:
                return level
        
        return 'Critical'  # Default for edge cases
    
    def get_risk_color(self, risk_level):
        """
        Get color code for risk level.
        
        Args:
            risk_level (str): Risk level
        
        Returns:
            str: Color code (hex)
        """
        colors = {
            'Low': '#16a34a',        # Green
            'Moderate': '#f59e0b',   # Orange
            'High': '#dc2626',       # Red
            'Critical': '#b91c1c'    # Dark Red
        }
        return colors.get(risk_level, '#6b7280')
    
    def get_confidence_indicator(self, scores_dict):
        """
        Calculate confidence in the detection.
        Higher confidence when multiple detectors agree.
        
        Args:
            scores_dict (dict): Dictionary with detection scores
        
        Returns:
            dict: Confidence metrics
        """
        scores = [
            scores_dict.get('keyword_score', 0),
            scores_dict.get('url_score', 0),
            scores_dict.get('regex_score', 0),
            scores_dict.get('ai_score', 0)
        ]
        
        # Count detectors that flagged the email
        flagged_count = sum(1 for s in scores if s > 30)
        
        # Confidence: how many detectors agree
        confidence = (flagged_count / len(scores)) * 100
        
        return {
            'confidence_percentage': confidence,
            'detectors_flagged': flagged_count,
            'total_detectors': len(scores),
            'consensus': 'Strong' if flagged_count >= 3 else 'Moderate' if flagged_count >= 2 else 'Weak'
        }
    
    def generate_risk_summary(self, score, risk_level, confidence):
        """
        Generate human-readable risk summary.
        
        Args:
            score (float): Risk score
            risk_level (str): Risk level
            confidence (dict): Confidence metrics
        
        Returns:
            dict: Summary with explanation
        """
        summaries = {
            'Low': 'This email appears to be legitimate. No major phishing indicators detected.',
            'Moderate': 'This email has some suspicious characteristics. Review carefully before clicking links.',
            'High': 'This email shows strong phishing indicators. Do not click links or download attachments.',
            'Critical': 'This email is very likely phishing. Do not interact with it. Report immediately.'
        }
        
        return {
            'score': round(score, 1),
            'level': risk_level,
            'summary': summaries.get(risk_level, 'Unknown'),
            'confidence': confidence['confidence_percentage'],
            'consensus': confidence['consensus'],
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level):
        """
        Get action recommendation based on risk level.
        
        Args:
            risk_level (str): Risk level
        
        Returns:
            str: Recommended action
        """
        recommendations = {
            'Low': '✓ Safe to interact with, but remain cautious',
            'Moderate': '⚠️ Review carefully before taking any action',
            'High': '❌ Do not click links or download attachments',
            'Critical': '🚨 Delete immediately and report as phishing'
        }
        
        return recommendations.get(risk_level, 'Unknown risk level')
    
    def validate_scores(self, scores_dict):
        """
        Validate that all scores are in valid ranges.
        
        Args:
            scores_dict (dict): Dictionary with detection scores
        
        Returns:
            tuple: (is_valid, error_message)
        """
        valid_ranges = {
            'keyword_score': (0, 30),
            'url_score': (0, 25),
            'regex_score': (0, 100),
            'ai_score': (0, 100)
        }
        
        for score_name, (min_val, max_val) in valid_ranges.items():
            score = scores_dict.get(score_name, 0)
            if not (min_val <= score <= max_val):
                return False, f'{score_name} out of range: {score}'
        
        return True, 'All scores valid'


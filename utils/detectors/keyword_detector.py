"""
Keyword Detection Module
Detects suspicious keywords and phrases in emails.
"""


class KeywordDetector:
    """
    Detects phishing-related keywords and phrases.
    This is the simplest form of detection.
    """
    
    def __init__(self):
        """Initialize keyword lists."""
        self.urgent_keywords = [
            'urgent', 'act now', 'immediately', 'within 24 hours',
            'within 48 hours', 'verify now', 'confirm now', 'click here',
            'click now', 'limited time', 'don\'t miss', 'free', 'claim',
            'your account will be closed', 'your account has been suspended',
            'your account has been locked', 'suspicious activity',
            'unusual activity', 'unauthorized access', 'verify your identity',
            'update your information', 're-enter your credentials'
        ]
        
        self.credential_keywords = [
            'password', 'otp', 'pin', 'social security',
            'credit card', 'bank account', 'login', 'verify identity',
            'confirm identity', 'authenticate', 'secret question',
            'cvv', 'expiration date', 'billing address'
        ]
        
        self.urgency_phrases = [
            'act now', 'immediately', 'urgent', 'asap',
            'right now', 'today', 'expires today', 'expires soon',
            'limited offer', 'last chance', 'hurry',
            'don\'t wait', 'final notice', 'last warning'
        ]
        
        self.fear_phrases = [
            'suspended', 'locked', 'closed', 'compromised',
            'unauthorized', 'illegal', 'violation', 'breach',
            'hacked', 'stolen', 'danger', 'risk', 'fraud',
            'criminal', 'legal action', 'penalties'
        ]
    
    def detect_urgent_keywords(self, text):
        """
        Detect urgent language in text.
        
        Args:
            text (str): Text to analyze
        
        Returns:
            list: List of urgent keywords found
        """
        text_lower = text.lower()
        found = []
        
        for keyword in self.urgent_keywords:
            if keyword in text_lower:
                found.append(keyword)
        
        return list(set(found))  # Remove duplicates
    
    def detect_credential_requests(self, text):
        """
        Detect requests for sensitive credentials.
        
        Args:
            text (str): Text to analyze
        
        Returns:
            list: List of credential keywords found
        """
        text_lower = text.lower()
        found = []
        
        for keyword in self.credential_keywords:
            if keyword in text_lower:
                found.append(keyword)
        
        return list(set(found))
    
    def detect_fear_tactics(self, text):
        """
        Detect emotional manipulation and fear tactics.
        
        Args:
            text (str): Text to analyze
        
        Returns:
            list: List of fear-related keywords found
        """
        text_lower = text.lower()
        found = []
        
        for keyword in self.fear_phrases:
            if keyword in text_lower:
                found.append(keyword)
        
        return list(set(found))
    
    def analyze_keywords(self, text):
        """
        Complete keyword analysis of text.
        
        Args:
            text (str): Text to analyze
        
        Returns:
            dict: Dictionary with all keyword findings
        """
        return {
            'urgent': self.detect_urgent_keywords(text),
            'credentials': self.detect_credential_requests(text),
            'fear_tactics': self.detect_fear_tactics(text)
        }
    
    def get_keyword_risk_score(self, keywords_found):
        """
        Calculate risk score based on keywords found.
        
        Args:
            keywords_found (dict): Dictionary from analyze_keywords()
        
        Returns:
            float: Risk score contribution (0-30)
        """
        score = 0
        
        # Urgent keywords: +3 points each (max 9)
        score += min(len(keywords_found['urgent']) * 3, 9)
        
        # Credential keywords: +5 points each (max 15)
        score += min(len(keywords_found['credentials']) * 5, 15)
        
        # Fear tactics: +2 points each (max 6)
        score += min(len(keywords_found['fear_tactics']) * 2, 6)
        
        return min(score, 30)  # Max 30 points


"""
Suspicious Sender Detection Module
Analyzes sender email address for phishing indicators.
"""

import re


class SenderDetector:
    """
    Detects suspicious sender patterns and characteristics.
    Checks if the sender email looks legitimate or fake.
    """
    
    def __init__(self):
        """Initialize sender detection patterns."""
        self.legitimate_domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'protonmail.com', 'icloud.com', 'mail.com'
        ]
        
        # Common brand domains (real companies)
        self.known_company_domains = {
            'paypal': ['paypal.com', 'ebay.com'],
            'amazon': ['amazon.com', 'amazon.co.uk'],
            'apple': ['apple.com', 'icloud.com'],
            'microsoft': ['microsoft.com', 'outlook.com'],
            'google': ['google.com', 'gmail.com'],
            'facebook': ['facebook.com', 'fb.com'],
            'twitter': ['twitter.com'],
            'linkedin': ['linkedin.com'],
            'bank': ['wellsfargo.com', 'chase.com', 'bankofamerica.com']
        }
    
    def extract_sender_info(self, sender_email):
        """
        Extract domain and username from sender email.
        
        Args:
            sender_email (str): Email address like "name@domain.com"
        
        Returns:
            dict: Dictionary with 'username' and 'domain'
        """
        if not sender_email or '@' not in sender_email:
            return {'username': 'Unknown', 'domain': 'Unknown'}
        
        try:
            parts = sender_email.split('@')
            return {
                'username': parts[0],
                'domain': parts[1].lower()
            }
        except Exception:
            return {'username': 'Unknown', 'domain': 'Unknown'}
    
    def is_free_email_service(self, domain):
        """
        Check if sender uses free email service (Gmail, Yahoo, etc).
        
        Args:
            domain (str): Email domain
        
        Returns:
            bool: True if free email service, False if company domain
        """
        return domain in self.legitimate_domains
    
    def detect_homograph_attack(self, sender_email):
        """
        Detect homograph attacks (similar looking but different domains).
        Example: "goog1e.com" looks like "google.com" but isn't
        
        Args:
            sender_email (str): Email address to check
        
        Returns:
            list: List of similar brand names found
        """
        sender_lower = sender_email.lower()
        suspicious_matches = []
        
        # Check for lookalike characters
        homograph_replacements = {
            '0': 'o',  # Zero looks like letter O
            '1': 'l',  # One looks like letter l
            '5': 's',  # Five looks like S
            '8': 'b',  # Eight looks like B
        }
        
        # Check each known company
        for company, domains in self.known_company_domains.items():
            # If sender claims to be from company but domain is different
            if company in sender_lower:
                for real_domain in domains:
                    if real_domain not in sender_lower:
                        # Email mentions company but uses different domain
                        suspicious_matches.append({
                            'type': 'brand_mismatch',
                            'company': company,
                            'claimed_domain': real_domain,
                            'actual_email': sender_email
                        })
        
        return suspicious_matches
    
    def detect_suspicious_patterns(self, sender_email):
        """
        Detect suspicious patterns in sender email.
        
        Args:
            sender_email (str): Email address
        
        Returns:
            list: List of suspicious patterns found
        """
        suspicious = []
        sender_lower = sender_email.lower()
        
        # Pattern 1: Generic sender names (might be fake)
        generic_names = ['noreply', 'notification', 'alert', 'admin', 'support', 'no-reply']
        for name in generic_names:
            if sender_lower.startswith(name + '@'):
                suspicious.append({
                    'type': 'generic_name',
                    'pattern': name,
                    'description': f'Generic sender name "{name}" might be automated'
                })
        
        # Pattern 2: Numbers instead of letters (homograph)
        if re.search(r'[0o1l5s8b]', sender_email):
            suspicious.append({
                'type': 'homograph_characters',
                'description': 'Email contains characters that look like letters (0→O, 1→l, etc)'
            })
        
        # Pattern 3: Too many numbers
        if len(re.findall(r'\d', sender_email)) > 5:
            suspicious.append({
                'type': 'excessive_numbers',
                'description': 'Sender email has unusually many numbers'
            })
        
        # Pattern 4: Unusual special characters
        if re.search(r'[!@#$%^&*()_+=\[\]{};:\'",<>?/\\|`~-]{2,}', sender_email):
            suspicious.append({
                'type': 'suspicious_characters',
                'description': 'Sender email contains unusual special characters'
            })
        
        return suspicious
    
    def check_sender_reputation(self, sender_email):
        """
        Check overall sender reputation.
        
        Args:
            sender_email (str): Email address
        
        Returns:
            dict: Reputation assessment
        """
        info = self.extract_sender_info(sender_email)
        domain = info['domain']
        
        reputation = {
            'sender': sender_email,
            'domain': domain,
            'is_free_email': self.is_free_email_service(domain),
            'homograph_attacks': self.detect_homograph_attack(sender_email),
            'suspicious_patterns': self.detect_suspicious_patterns(sender_email),
            'risk_level': 'Low'
        }
        
        # Calculate risk level
        if reputation['homograph_attacks'] or reputation['suspicious_patterns']:
            reputation['risk_level'] = 'High'
        elif reputation['is_free_email']:
            reputation['risk_level'] = 'Moderate'
        
        return reputation
    
    def get_sender_risk_score(self, sender_email):
        """
        Calculate risk score for sender (0-20 points).
        
        Args:
            sender_email (str): Email address
        
        Returns:
            float: Risk score (0-20)
        """
        score = 0
        reputation = self.check_sender_reputation(sender_email)
        
        # Homograph attacks: +10 points each (very suspicious)
        score += len(reputation['homograph_attacks']) * 10
        
        # Suspicious patterns: +5 points each
        score += len(reputation['suspicious_patterns']) * 5
        
        # Free email service: +2 points (less risky but worth noting)
        if reputation['is_free_email']:
            score += 2
        
        return min(score, 20)  # Max 20 points

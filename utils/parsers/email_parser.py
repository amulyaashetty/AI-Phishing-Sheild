"""
Email Parser Module
Extracts and cleans email content for analysis.
"""

import re
from email.mime.text import MIMEText


class EmailParser:
    """
    Parses email content and extracts relevant information.
    Handles both plain text email input and .eml files.
    """
    
    def __init__(self, email_content):
        """
        Initialize email parser with email content.
        
        Args:
            email_content (str): Raw email text
        """
        self.raw_content = email_content
        self.cleaned_content = self._clean_email()
        self.extracted_info = self._extract_email_info()
    
    def _clean_email(self):
        """
        Remove extra whitespace and normalize email content.
        
        Returns:
            str: Cleaned email content
        """
        # Remove extra whitespace
        cleaned = self.raw_content.strip()
        
        # Remove multiple consecutive newlines
        cleaned = re.sub(r'\n\n+', '\n\n', cleaned)
        
        return cleaned
    
    def _extract_email_info(self):
        """
        Extract key information from email.
        
        Returns:
            dict: Dictionary with extracted email components
        """
        info = {
            'sender': self._extract_sender(),
            'subject': self._extract_subject(),
            'body': self._extract_body(),
            'links': self._extract_links(),
            'emails': self._extract_emails(),
            'phone_numbers': self._extract_phone_numbers()
        }
        return info
    
    def _extract_sender(self):
        """
        Extract sender email address from content.
        
        Returns:
            str: Sender email or empty string
        """
        # Look for "From:" in common email formats
        from_pattern = r'From:\s*([^\n]+)'
        match = re.search(from_pattern, self.cleaned_content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""
    
    def _extract_subject(self):
        """
        Extract email subject line.
        
        Returns:
            str: Subject line or empty string
        """
        # Look for "Subject:" line
        subject_pattern = r'Subject:\s*([^\n]+)'
        match = re.search(subject_pattern, self.cleaned_content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""
    
    def _extract_body(self):
        """
        Extract email body (everything after headers).
        
        Returns:
            str: Email body text
        """
        # Simple approach: assume body starts after headers
        # Headers typically end with double newline
        parts = self.cleaned_content.split('\n\n', 1)
        if len(parts) > 1:
            return parts[1]
        return self.cleaned_content
    
    def _extract_links(self):
        """
        Extract all URLs/links from email.
        
        Returns:
            list: List of URLs found in email
        """
        # Pattern for URLs
        url_pattern = r'https?://[^\s\n<>"\)\]]+|www\.[^\s\n<>"\)\]]+'
        links = re.findall(url_pattern, self.cleaned_content, re.IGNORECASE)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_links = []
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)
        
        return unique_links
    
    def _extract_emails(self):
        """
        Extract all email addresses from content.
        
        Returns:
            list: List of email addresses found
        """
        # Email pattern
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, self.cleaned_content)
        
        # Remove duplicates
        return list(set(emails))
    
    def _extract_phone_numbers(self):
        """
        Extract phone numbers from content.
        
        Returns:
            list: List of phone numbers found
        """
        # Common phone number patterns
        phone_pattern = r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        phones = re.findall(phone_pattern, self.cleaned_content)
        
        # Remove duplicates
        return list(set(phones))
    
    def get_extracted_info(self):
        """
        Get all extracted email information.
        
        Returns:
            dict: Dictionary with sender, subject, body, links, etc.
        """
        return self.extracted_info
    
    def get_full_text(self):
        """
        Get cleaned email full text.
        
        Returns:
            str: Cleaned email content
        """
        return self.cleaned_content

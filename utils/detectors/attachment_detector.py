"""
Attachment Detection Module
Scans for dangerous file types and malicious attachments.
"""

import re


class AttachmentDetector:
    """
    Detects dangerous attachments that could contain malware.
    Checks file extensions and characteristics.
    """
    
    def __init__(self):
        """Initialize dangerous file types."""
        
        # CRITICAL: Definitely malware/phishing
        self.critical_extensions = [
            'exe',   # Windows executable
            'scr',   # Screensaver (often malware)
            'bat',   # Batch file
            'cmd',   # Command file
            'com',   # DOS executable
            'pif',   # Program info file
            'msi',   # Windows installer
            'vbs',   # Visual Basic script
            'js',    # JavaScript (can be malicious)
            'jar',   # Java archive
            'zip',   # Compressed files (often contain malware)
            'rar',   # Compressed files
            '7z',    # Compressed files
        ]
        
        # HIGH RISK: Macro-enabled Office files
        self.macro_extensions = [
            'docm',  # Word with macros
            'xlsm',  # Excel with macros
            'pptm',  # PowerPoint with macros
            'xlam',  # Excel add-in with macros
        ]
        
        # MEDIUM RISK: Office files (can have embedded objects)
        self.office_extensions = [
            'doc',   # Word document
            'xls',   # Excel spreadsheet
            'ppt',   # PowerPoint
            'csv',  # Comma-separated values
        ]
        
        # LOW RISK: Generally safe
        self.safe_extensions = [
            'pdf',   # PDF files
            'txt',   # Text files
            'jpg', 'jpeg', 'png', 'gif',  # Images
            'mp3', 'mp4', 'mov', 'avi',   # Media
        ]
    
    def extract_attachments(self, email_content):
        """
        Extract attachment filenames from email content.
        Looks for common attachment patterns.
        
        Args:
            email_content (str): Raw email text
        
        Returns:
            list: List of filenames found
        """
        # Patterns like "Attachment: filename.doc" or "[file.zip attached]"
        patterns = [
            r'Attachment:\s*([^\s\n]+)',
            r'Attached:\s*([^\s\n]+)',
            r'\[([^\]]+\.\w+)\s*attached\]',
            r'File:\s*([^\s\n]+)',
            r'Filename:\s*([^\s\n]+)',
        ]
        
        attachments = []
        for pattern in patterns:
            matches = re.findall(pattern, email_content, re.IGNORECASE)
            attachments.extend(matches)
        
        # Remove duplicates
        return list(set(attachments))
    
    def get_file_extension(self, filename):
        """
        Get file extension from filename.
        
        Args:
            filename (str): Filename like "document.docm"
        
        Returns:
            str: Extension like "docm"
        """
        if '.' not in filename:
            return ''
        
        return filename.split('.')[-1].lower()
    
    def classify_file_risk(self, filename):
        """
        Classify file risk level based on extension.
        
        Args:
            filename (str): Filename to check
        
        Returns:
            dict: Classification with risk level and details
        """
        ext = self.get_file_extension(filename)
        
        classification = {
            'filename': filename,
            'extension': ext,
            'risk_level': 'Unknown',
            'reason': ''
        }
        
        if ext in self.critical_extensions:
            classification['risk_level'] = 'Critical'
            classification['reason'] = f'.{ext} files are commonly used for malware distribution'
        
        elif ext in self.macro_extensions:
            classification['risk_level'] = 'High'
            classification['reason'] = f'.{ext} files can contain malicious macros'
        
        elif ext in self.office_extensions:
            classification['risk_level'] = 'Medium'
            classification['reason'] = f'.{ext} files can contain embedded objects/malware'
        
        elif ext in self.safe_extensions:
            classification['risk_level'] = 'Low'
            classification['reason'] = f'.{ext} files are generally safe'
        
        else:
            classification['risk_level'] = 'Unknown'
            classification['reason'] = f'.{ext} is an unknown file type - exercise caution'
        
        return classification
    
    def detect_suspicious_characteristics(self, filename):
        """
        Detect suspicious filename patterns.
        
        Args:
            filename (str): Filename to analyze
        
        Returns:
            list: List of suspicious characteristics found
        """
        suspicious = []
        
        # Pattern 1: Double extension (file.pdf.exe - tries to hide .exe)
        parts = filename.split('.')
        if len(parts) > 2:
            first_ext = parts[-2].lower()
            second_ext = parts[-1].lower()
            
            # If looks like one type but actually is executable
            if first_ext in self.safe_extensions and second_ext in self.critical_extensions:
                suspicious.append({
                    'type': 'double_extension',
                    'description': f'Double extension hiding: .{first_ext}.{second_ext}',
                    'severity': 'Critical'
                })
        
        # Pattern 2: Spaces or special characters (trying to hide extension)
        if re.search(r'\s+\.\w+$', filename):
            suspicious.append({
                'type': 'hidden_extension',
                'description': 'Spaces before extension - might hide true file type',
                'severity': 'High'
            })
        
        # Pattern 3: Unusual characters
        if re.search(r'[<>:"/\\|?*]', filename):
            suspicious.append({
                'type': 'invalid_characters',
                'description': 'Filename contains invalid characters',
                'severity': 'Medium'
            })
        
        # Pattern 4: Very long filename (might bypass filters)
        if len(filename) > 255:
            suspicious.append({
                'type': 'excessive_length',
                'description': 'Filename is unusually long',
                'severity': 'Medium'
            })
        
        return suspicious
    
    def analyze_attachments(self, email_content):
        """
        Complete attachment analysis.
        
        Args:
            email_content (str): Raw email text
        
        Returns:
            dict: Complete attachment analysis
        """
        attachments = self.extract_attachments(email_content)
        
        analysis = {
            'attachment_count': len(attachments),
            'attachments': [],
            'has_critical_files': False,
            'has_macro_files': False
        }
        
        for filename in attachments:
            classification = self.classify_file_risk(filename)
            suspicious_chars = self.detect_suspicious_characteristics(filename)
            
            attachment_info = {
                'filename': filename,
                'classification': classification,
                'suspicious_characteristics': suspicious_chars
            }
            
            analysis['attachments'].append(attachment_info)
            
            # Update flags
            if classification['risk_level'] == 'Critical':
                analysis['has_critical_files'] = True
            if classification['risk_level'] == 'High':
                analysis['has_macro_files'] = True
        
        return analysis
    
    def get_attachment_risk_score(self, email_content):
        """
        Calculate risk score for attachments (0-15 points).
        
        Args:
            email_content (str): Raw email text
        
        Returns:
            float: Risk score (0-15)
        """
        analysis = self.analyze_attachments(email_content)
        score = 0
        
        # Critical files: +10 points each
        for attachment in analysis['attachments']:
            if attachment['classification']['risk_level'] == 'Critical':
                score += 10
            elif attachment['classification']['risk_level'] == 'High':
                score += 5
            elif attachment['classification']['risk_level'] == 'Medium':
                score += 2
        
        # Suspicious characteristics: +3 points each
        for attachment in analysis['attachments']:
            score += len(attachment['suspicious_characteristics']) * 3
        
        return min(score, 15)  # Max 15 points

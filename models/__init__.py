"""
AI Analysis Module
Uses OpenAI API for intelligent phishing detection reasoning.
Provides context-aware analysis and explanations.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class AIAnalyzer:
    """
    Uses OpenAI's API to provide intelligent phishing analysis.
    This module handles AI-based reasoning about potential phishing attacks.
    """
    
    def __init__(self):
        """Initialize AI analyzer with OpenAI API key."""
        self.api_key = os.getenv('OPENAI_API_KEY')
        
        # If using OpenAI, we'll use requests to call the API
        self.model = "gpt-3.5-turbo"  # You can also use "gpt-4" if available
    
    def analyze_email(self, email_content, extracted_info):
        """
        Analyze email content using AI.
        
        Args:
            email_content (str): Full email text
            extracted_info (dict): Extracted email components
        
        Returns:
            dict: AI analysis with explanation and reasoning
        """
        
        # If API key is not available, provide fallback analysis
        if not self.api_key:
            return self._fallback_analysis(email_content, extracted_info)
        
        try:
            # Create prompt for AI analysis
            prompt = self._create_analysis_prompt(email_content, extracted_info)
            
            # Call OpenAI API
            response = self._call_openai_api(prompt)
            
            # Parse response
            analysis = self._parse_ai_response(response)
            
            return analysis
            
        except Exception as e:
            print(f"Error in AI analysis: {str(e)}")
            return self._fallback_analysis(email_content, extracted_info)
    
    def _create_analysis_prompt(self, email_content, extracted_info):
        """
        Create a detailed prompt for AI analysis.
        
        Args:
            email_content (str): Email text
            extracted_info (dict): Extracted components
        
        Returns:
            str: Formatted prompt for OpenAI
        """
        prompt = f"""
You are a cybersecurity expert analyzing emails for phishing threats.
Analyze the following email and provide a structured assessment.

EMAIL CONTENT:
---
{email_content}
---

EXTRACTED INFORMATION:
- Sender: {extracted_info.get('sender', 'Unknown')}
- Subject: {extracted_info.get('subject', 'No subject')}
- Links: {', '.join(extracted_info.get('links', [])) or 'None'}
- Email addresses: {', '.join(extracted_info.get('emails', [])) or 'None'}

Please provide your analysis in the following format:
1. RISK_ASSESSMENT: [High/Moderate/Low] - Your overall assessment
2. KEY_CONCERNS: [List 3-4 main phishing indicators you noticed]
3. REASONING: [Explain why this might be phishing]
4. RECOMMENDATIONS: [What should the user do?]
5. CONFIDENCE: [Your confidence level 0-100]

Be concise and educational. Explain technical terms simply.
"""
        return prompt
    
    def _call_openai_api(self, prompt):
        """
        Call OpenAI API with prompt.
        
        Args:
            prompt (str): Analysis prompt
        
        Returns:
            str: AI response
        """
        import requests
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert specializing in phishing detection. Provide clear, educational analysis."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 500
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            raise Exception(f"API Error: {response.status_code}")
    
    def _parse_ai_response(self, response):
        """
        Parse AI response into structured format.
        
        Args:
            response (str): AI response text
        
        Returns:
            dict: Parsed analysis
        """
        analysis = {
            'ai_explanation': response,
            'risk_level': 'Moderate',
            'key_concerns': [],
            'recommendations': []
        }
        
        # Simple parsing of response
        if 'high' in response.lower():
            analysis['risk_level'] = 'High'
        elif 'low' in response.lower():
            analysis['risk_level'] = 'Low'
        elif 'critical' in response.lower():
            analysis['risk_level'] = 'Critical'
        
        # Extract recommendations if present
        if 'RECOMMENDATIONS:' in response:
            rec_section = response.split('RECOMMENDATIONS:')[1]
            analysis['recommendations'] = [
                line.strip() for line in rec_section.split('\n') 
                if line.strip() and line.strip().startswith('-')
            ]
        
        return analysis
    
    def _fallback_analysis(self, email_content, extracted_info):
        """
        Provide analysis when API is not available.
        Uses heuristics and pattern-based reasoning.
        
        Args:
            email_content (str): Email text
            extracted_info (dict): Extracted components
        
        Returns:
            dict: Fallback analysis
        """
        sender = extracted_info.get('sender', '').lower()
        subject = extracted_info.get('subject', '').lower()
        links = extracted_info.get('links', [])
        
        # Determine risk based on heuristics
        risk_indicators = 0
        concerns = []
        
        if not sender or 'noreply' in sender or 'no-reply' in sender:
            risk_indicators += 1
            concerns.append("Sender appears to be automated/noreply address")
        
        if any(urgent in subject for urgent in ['urgent', 'verify', 'confirm', 'action']):
            risk_indicators += 1
            concerns.append("Subject uses urgency language")
        
        if links:
            risk_indicators += 1
            concerns.append("Email contains suspicious links")
        
        # Set risk level
        if risk_indicators >= 3:
            risk_level = 'High'
        elif risk_indicators >= 2:
            risk_level = 'Moderate'
        else:
            risk_level = 'Low'
        
        return {
            'ai_explanation': (
                "AI Analysis not available (API key not configured). "
                "Based on pattern analysis: This email shows characteristics common in phishing attempts. "
                "Be cautious with links and credential requests."
            ),
            'risk_level': risk_level,
            'key_concerns': concerns,
            'recommendations': [
                "Do not click links or download attachments",
                "Contact the organization directly using a known phone number",
                "Report the email as phishing to your email provider"
            ]
        }


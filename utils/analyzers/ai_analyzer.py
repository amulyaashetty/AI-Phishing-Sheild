"""
AI Analyzer Module
Uses Ollama local LLM for intelligent phishing detection reasoning.
"""

import requests


class AIAnalyzer:
    """Uses Ollama's local LLM to provide intelligent phishing analysis."""
    
    def __init__(self):
        """Initialize AI analyzer with Ollama connection."""
        self.ollama_url = "http://localhost:11434/api/generate"
        self.model = "orca-mini"  # Using orca-mini (lightweight and fast)
        self.ollama_available = self._check_ollama_connection()
    
    def _check_ollama_connection(self):
        """Check if Ollama is running."""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            return response.status_code == 200
        except Exception:
            return False
    
    def analyze_email(self, email_content, extracted_info):
        """
        Analyze email using Ollama AI.
        
        Args:
            email_content (str): Email text
            extracted_info (dict): Extracted email components
        
        Returns:
            dict: AI analysis results
        """
        if not self.ollama_available:
            return self._fallback_analysis(email_content, extracted_info)
        
        try:
            prompt = self._create_analysis_prompt(email_content, extracted_info)
            response = self._call_ollama_api(prompt)
            analysis = self._parse_ai_response(response)
            return analysis
        except Exception as e:
            print(f"Ollama API Error: {str(e)}")
            return self._fallback_analysis(email_content, extracted_info)
    
    def _create_analysis_prompt(self, email_content, extracted_info):
        """Create prompt for AI analysis."""
        prompt = f"""You are a cybersecurity expert analyzing emails for phishing. Be concise.

EMAIL CONTENT:
{email_content[:800]}

---
DETAILS:
- Sender: {extracted_info.get('sender', 'Unknown')}
- Subject: {extracted_info.get('subject', 'No subject')}
- Links found: {len(extracted_info.get('links', []))}

ANALYZE THIS EMAIL AND RESPOND WITH:
1. RISK LEVEL: [High/Moderate/Low]
2. TOP 3 CONCERNS: [List specific red flags]
3. EXPLANATION: [Why this risk level]
4. RECOMMENDATION: [What the user should do]

Keep response concise and professional."""
        return prompt
    
    def _call_ollama_api(self, prompt):
        """Call Ollama API."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.5
        }
        
        response = requests.post(
            self.ollama_url,
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()["response"]
        raise Exception(f"Ollama error: {response.status_code}")
    
    def _parse_ai_response(self, response):
        """Parse AI response to extract risk level."""
        response_lower = response.lower()
        
        risk_level = 'Moderate'
        if 'high risk' in response_lower or 'very suspicious' in response_lower:
            risk_level = 'High'
        elif 'low risk' in response_lower or 'appears safe' in response_lower or 'legitimate' in response_lower:
            risk_level = 'Low'
        elif 'critical' in response_lower:
            risk_level = 'High'
        
        return {
            'ai_explanation': response,
            'risk_level': risk_level,
            'key_concerns': ['See detailed AI analysis above'],
            'recommendations': ['Review AI analysis carefully']
        }
    
    def _fallback_analysis(self, email_content, extracted_info):
        """Fallback analysis when Ollama is not available."""
        return {
            'ai_explanation': (
                "⚠️ Ollama AI not available. Make sure Ollama is running:\n"
                "1. Install Ollama from https://ollama.ai\n"
                "2. Run: ollama pull mistral\n"
                "3. Run: ollama serve\n"
                "Using rule-based detection only."
            ),
            'risk_level': 'Moderate',
            'key_concerns': [
                'AI model not accessible',
                'Relying on pattern-based detection only'
            ],
            'recommendations': [
                'Start Ollama service for full AI analysis',
                'Use rule-based detection results cautiously'
            ]
        }

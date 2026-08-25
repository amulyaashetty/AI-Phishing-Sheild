"""
AI Analyzer Module
Uses Ollama local LLM for intelligent phishing detection reasoning.
"""

import requests


class AIAnalyzer:
    """Uses Ollama's local LLM to provide intelligent phishing analysis."""
    
    def __init__(self):
        """Initialize AI analyzer with Ollama connection."""
        self.ollama_url = "http://localhost:11434/api/chat"  # Using chat API (supports system/user messages)
        self.model = "mistral"  # Using Mistral (better reasoning and phishing detection)
        self.ollama_available = self._check_ollama_connection()
        
        # System prompt (AI's role and behavior)
        self.system_prompt = (
            "You are a cybersecurity expert specializing in phishing email detection. "
            "Analyze emails for phishing indicators and provide clear, concise assessments. "
            "Focus on: sender authenticity, URL legitimacy, urgency tactics, requests for credentials, "
            "and suspicious attachments. Be professional and direct."
        )
    
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
        """Create user prompt for AI analysis (system prompt is separate)."""
        user_prompt = f"""Please analyze the following email for phishing indicators:

EMAIL CONTENT:
{email_content[:800]}

---
EMAIL DETAILS:
- Sender: {extracted_info.get('sender', 'Unknown')}
- Subject: {extracted_info.get('subject', 'No subject')}
- Links found: {len(extracted_info.get('links', []))}

Provide your analysis in this format:
1. RISK LEVEL: [High/Moderate/Low]
2. TOP 3 CONCERNS: [List specific red flags found]
3. EXPLANATION: [Why this email has this risk level]
4. RECOMMENDATION: [What the user should do]
5. Give some examples of similar phishing emails and how to avoid them

Be concise and professional."""
        return user_prompt
    
    def _call_ollama_api(self, user_prompt):
        """Call Ollama Chat API with system and user messages."""
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": self.system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            "stream": False,
            "temperature": 0.5
        }
        
        response = requests.post(
            self.ollama_url,
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()["message"]["content"]
        raise Exception(f"Ollama error: {response.status_code}")
    
    def _parse_ai_response(self, response):
        """Parse AI response to extract risk level and structured points."""
        response_lower = response.lower()
        
        risk_level = 'Moderate'
        if 'high risk' in response_lower or 'very suspicious' in response_lower:
            risk_level = 'High'
        elif 'low risk' in response_lower or 'appears safe' in response_lower or 'legitimate' in response_lower:
            risk_level = 'Low'
        elif 'critical' in response_lower:
            risk_level = 'High'
        
        # Parse response into structured sections
        sections = self._extract_sections(response)
        
        return {
            'ai_explanation': response,
            'risk_level': risk_level,
            'risk_level_text': sections.get('risk_level', ''),
            'top_concerns': sections.get('concerns', []),
            'explanation': sections.get('explanation', ''),
            'recommendation': sections.get('recommendation', ''),
            'key_concerns': sections.get('concerns', ['See detailed AI analysis above']),
            'recommendations': sections.get('recommendation_bullets', ['Review AI analysis carefully'])
        }
    
    def _extract_sections(self, response):
        """Extract structured sections from AI response."""
        sections = {
            'risk_level': '',
            'concerns': [],
            'explanation': '',
            'recommendation': '',
            'recommendation_bullets': []
        }
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect section headers
            if line.startswith('1.') or 'RISK LEVEL' in line.upper():
                current_section = 'risk_level'
                sections['risk_level'] = line.replace('1.', '').replace('RISK LEVEL:', '').strip()
            elif line.startswith('2.') or 'TOP 3 CONCERNS' in line.upper():
                current_section = 'concerns'
            elif line.startswith('3.') or 'EXPLANATION' in line.upper():
                current_section = 'explanation'
            elif line.startswith('4.') or 'RECOMMENDATION' in line.upper():
                current_section = 'recommendation'
            elif current_section and line:
                # Add content to current section
                if current_section == 'concerns':
                    # Clean up bullet points
                    clean_line = line.lstrip('-•*').strip()
                    if clean_line:
                        sections['concerns'].append(clean_line)
                elif current_section == 'explanation':
                    sections['explanation'] += ' ' + line
                elif current_section == 'recommendation':
                    clean_line = line.lstrip('-•*').strip()
                    if clean_line:
                        sections['recommendation_bullets'].append(clean_line)
                    if not sections['recommendation']:
                        sections['recommendation'] = clean_line
        
        return sections
    
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

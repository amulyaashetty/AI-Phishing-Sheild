"""
Utils Package
Contains all utility modules organized by category:
- parsers: Email and content parsing
- detectors: Phishing detection engines
- analyzers: Risk calculation and AI analysis
- helpers: Common helper functions
"""

# Import from submodules for easy access
from .parsers import EmailParser
from .detectors import RegexDetector, KeywordDetector, URLDetector
from .analyzers import RiskCalculator, AIAnalyzer
from .helpers import (
    TextHelpers, EmailHelpers, ValidationHelpers,
    DateTimeHelpers, RenderHelpers
)

__all__ = [
    'EmailParser',
    'RegexDetector',
    'KeywordDetector',
    'URLDetector',
    'RiskCalculator',
    'AIAnalyzer',
    'TextHelpers',
    'EmailHelpers',
    'ValidationHelpers',
    'DateTimeHelpers',
    'RenderHelpers'
]



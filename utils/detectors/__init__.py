"""Detector modules for phishing pattern recognition."""

from .regex_detector import RegexDetector
from .keyword_detector import KeywordDetector
from .url_detector import URLDetector
from .sender_detector import SenderDetector
from .attachment_detector import AttachmentDetector

__all__ = ['RegexDetector', 'KeywordDetector', 'URLDetector', 'SenderDetector', 'AttachmentDetector']

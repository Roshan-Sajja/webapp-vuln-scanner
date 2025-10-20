
from .sqli import detect_sqli
from .xss import detect_xss

ALL_CHECKS = [
    ('SQLi', detect_sqli),
    ('XSS', detect_xss),
]
# Configuration settings for alert thresholds
ALERT_THRESHOLD = {
    'windows': {
        'login_failures': 5,
        'unauthorized_access': True,
        'privilege_escalation': True,
    },
    # Additional OS configurations can be added
}

# Default alert levels
ALERT_LEVELS = {
    'low': 'Low',
    'medium': 'Medium',
    'high': 'High',
}

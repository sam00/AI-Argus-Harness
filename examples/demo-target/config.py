# Synthetic config used to exercise the secrets scanner.
# NONE of these are real credentials — do not add real secrets here.

# AWS's own documented example key (non-functional):
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Random, non-functional high-entropy strings:
api_key = "abcdef0123456789abcdef0123456789"
DB_PASSWORD = "sup3rs3cretpassword"

# A placeholder that the scanner should IGNORE (template / not a real secret):
PLACEHOLDER_TOKEN = "${ENV_TOKEN}"
EXAMPLE_PASSWORD = "changeme"

import re


SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9_-]+",
    r"api[_ -]?key\s*[:=]?\s*[a-zA-Z0-9_-]+",
    r"password\s*[:=]?\s*\S+",
    r"token\s*[:=]?\s*[a-zA-Z0-9_-]+",
]


def detect_secrets(response):
    findings = []

    for pattern in SECRET_PATTERNS:
        matches = re.findall(pattern, response, re.IGNORECASE)

        for match in matches:
            findings.append({
                "type": "Sensitive Information Disclosure",
                "severity": "CRITICAL",
                "evidence": match
            })

    return findings

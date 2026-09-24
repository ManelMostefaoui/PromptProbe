from .secrets import detect_secrets
from .leakage import detect_leakage
from .actions import detect_actions
from .injection import detect_injection


def analyze(payload, response, category=None, technique=None):
    findings = []

    findings.extend(detect_secrets(response))
    findings.extend(detect_leakage(response))
    findings.extend(detect_actions(response))
    findings.extend(
        detect_injection(payload, response)
    )

    return findings

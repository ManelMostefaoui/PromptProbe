def calculate_score(scores):
    if not scores:
        return 0

    score = sum(scores) / len(scores)

    return round(min(score, 10), 1)


def get_risk_level(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "SAFE"

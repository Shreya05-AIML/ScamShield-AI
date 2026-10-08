from flask import Flask, render_template, request

app = Flask(__name__)


def analyze_message(message):
    message_lower = message.lower()

    score = 0
    warnings = []

    # Scam-related keywords
    scam_words = [
        "won", "winner", "prize", "lottery",
        "urgent", "immediately", "claim",
        "free", "reward", "congratulations"
    ]

    for word in scam_words:
        if word in message_lower:
            score += 10
            warnings.append(f"Suspicious word detected: '{word}'")

    # Sensitive information
    sensitive_words = [
        "otp", "password", "pin",
        "bank details", "credit card",
        "debit card", "cvv"
    ]

    for word in sensitive_words:
        if word in message_lower:
            score += 20
            warnings.append(f"Request for sensitive information: '{word}'")

    # Links
    if "http://" in message_lower or "https://" in message_lower or "www." in message_lower:
        score += 20
        warnings.append("Message contains a link")

    # Urgency
    if "click now" in message_lower or "act now" in message_lower:
        score += 20
        warnings.append("Creates a sense of urgency")

    # Limit score
    score = min(score, 100)

    # Risk level
    if score >= 60:
        risk = "HIGH RISK"
        recommendation = "Do not click links or share personal/banking information."
    elif score >= 30:
        risk = "MEDIUM RISK"
        recommendation = "Be careful. Verify the sender before taking any action."
    else:
        risk = "LOW RISK"
        recommendation = "No major scam indicators were detected, but stay cautious."

    if not warnings:
        warnings.append("No obvious scam indicators detected.")

    return risk, score, warnings, recommendation


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":
        message = request.form.get("message", "")

        risk, score, warnings, recommendation = analyze_message(message)

        result = {
            "risk": risk,
            "score": score,
            "warnings": warnings,
            "recommendation": recommendation
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env if present

from flask import Flask, render_template, request
from engine import ScamShieldEngine

app = Flask(__name__)
engine = ScamShieldEngine()

# Predefined realistic demo samples for 1-click testing
DEMO_SAMPLES = [
    {
        "id": "bank_kyc",
        "title": "🏦 Bank KYC Phishing",
        "tag": "High Risk",
        "text": "Dear customer, your SBI account has been suspended due to pending KYC. Click now to verify OTP and bank details immediately at https://bit.ly/sbi-kyc-verify to avoid permanent block."
    },
    {
        "id": "lottery",
        "title": "🏆 Lottery Scam",
        "tag": "High Risk",
        "text": "Congratulations! You have won ₹25,00,000 in KBC Lucky Draw 2026. Claim your cash reward immediately. Send your bank details to bit.ly/claim-kbc-reward now."
    },
    {
        "id": "part_time_job",
        "title": "💼 Part-Time Job Scam",
        "tag": "Medium Risk",
        "text": "Urgent hiring! Work from home and earn ₹5000 daily by simply liking YouTube videos. No experience needed. Join telegram immediately: t.me/daily_task_income"
    },
    {
        "id": "digital_arrest",
        "title": "🚨 Digital Arrest Extortion",
        "tag": "Medium Risk",
        "text": "URGENT NOTICE: A parcel containing narcotics was intercepted in your name by Customs. Police arrest warrant issued. Contact Cyber Crime Department immediately."
    },
    {
        "id": "delivery",
        "title": "📦 Courier Delivery Phishing",
        "tag": "Medium Risk",
        "text": "India Post: Your package could not be delivered due to an incomplete address. Please act now to update your address at http://indiapost-update.xyz/track"
    },
    {
        "id": "legit_bank",
        "title": "✅ Legitimate Bank Alert",
        "tag": "Safe / Low Risk",
        "text": "INR 1,250.00 debited from A/C XX4921 on 08-Oct-2026 via UPI to Swiggy. UPI Ref 428190248190. If not done by you, forward this SMS to 9223008333 to block card."
    }
]


def analyze_message(message):
    """Preserves exact backwards compatibility for any external callers."""
    res = engine.analyze(message)
    return res["risk"], res["score"], res["warnings"], res["recommendation"], res["risk_class"]


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "")

        if not message or not message.strip():
            error = "Please enter a message or URL to analyze."
        else:
            result = engine.analyze(message)

    return render_template("index.html", result=result, message=message, error=error, demo_samples=DEMO_SAMPLES)


if __name__ == "__main__":
    app.run(debug=True)
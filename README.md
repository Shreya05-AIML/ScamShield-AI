# 🛡️ ScamShield AI

**AI-Powered Scam, Phishing & Social Engineering Detection**

ScamShield AI is a cybersecurity web application that combines Google Gemini AI and rule-based detection to identify suspicious messages, assess scam risks, and recommend safe actions.

## ✨ Features

* 🤖 Google Gemini AI-powered message analysis
* 🚨 Risk classification: High, Medium, and Low
* 📊 Risk score out of 100
* 🔍 Detection of phishing links and suspicious requests
* 🧠 Identification of psychological manipulation tactics
* 🛡️ Practical safety recommendations
* 🇮🇳 Indian cybercrime reporting resources
* 🔄 Rule-based fallback when AI is unavailable

## 🧰 Technologies Used

* Python
* Flask
* Google Gemini API
* HTML and CSS
* Google GenAI SDK
* python-dotenv

## 🚀 Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Shreya05-AIML/ScamShield-AI.git
cd ScamShield-AI
```

### 2. Create a virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the Gemini API key

Create a `.env` file in the project folder and add:

```text
GEMINI_API_KEY=your_gemini_api_key_here
```

Replace the placeholder with your own API key. Never upload your real `.env` file or share your API key publicly.

### 5. Run the application

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## 🧪 Example Scenarios

* Bank KYC phishing messages
* Lottery and prize scams
* Fake part-time job offers
* Digital arrest extortion
* Courier delivery phishing
* Legitimate bank alerts

## 🇮🇳 Cyber Safety Resources

* **Cybercrime helpline:** 1930
* **Report cybercrime:** https://cybercrime.gov.in/
* **Sanchar Saathi:** https://sancharsaathi.gov.in/

## ⚠️ Disclaimer

ScamShield AI is a prototype and may make incorrect assessments. A low-risk result does not guarantee that a message or link is safe. Always verify messages through official channels, and never share passwords, OTPs, or banking credentials.

## 🎯 Project Objective

To improve digital safety by helping users recognize potential scams and make informed decisions before responding to suspicious messages.

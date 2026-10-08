import os
import re
import json
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


class PsychologicalTacticItem(BaseModel):
    name: str = Field(description="Name of tactic, e.g. Artificial Urgency, Fear & Coercion, Greed/Reward, Authority Impersonation, Credential Harvesting")
    explanation: str = Field(description="Brief explanation of how the tactic is applied in this message")


class GeminiScamAnalysis(BaseModel):
    scam_likelihood_score: int = Field(description="Scam likelihood score from 0 to 100")
    risk_level: str = Field(description="HIGH RISK, MEDIUM RISK, or LOW RISK")
    primary_category: str = Field(description="Primary scam category, e.g. Banking & Financial Fraud, Lottery & Prize Scam, Part-Time Job Scam, Law Enforcement & Digital Arrest, Delivery & Courier Phishing, or Legitimate / Low Suspicion")
    detected_categories: List[str] = Field(description="List of all applicable categories")
    psychological_tactics: List[PsychologicalTacticItem] = Field(description="List of detected psychological manipulation tactics")
    suspicious_requests: List[str] = Field(description="Specific suspicious requests found, e.g. OTP, PIN, bank details, clicking link")
    plain_english_explanation: str = Field(description="Clear explanation in simple plain English of why this message is safe or suspicious")
    recommended_actions: List[str] = Field(description="Actionable safety guidance for the user")


class BaseAIEngine:
    """Abstract interface for Phase 3 LLM integration."""
    def is_available(self) -> bool:
        return False

    def analyze(self, message: str, context: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("AI engine integration will be implemented in subclass.")


class GeminiAIEngine(BaseAIEngine):
    """Google Gemini AI integration using the official Google GenAI SDK with structured output."""

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        # Read API key strictly from parameter or environment variable
        self.api_key = (api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
        self.model_name = (model_name or os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")).strip()
        self.client = None

        if GENAI_AVAILABLE and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                # Never print or expose the API key on failure
                self.client = None

    def is_available(self) -> bool:
        return bool(self.client is not None and self.api_key)

    def analyze(self, message: str, context: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        if not self.is_available():
            return None

        system_instruction = (
            "You are ScamShield AI, an expert cybersecurity and digital fraud prevention assistant. "
            "Analyze the given message/URL for scam, phishing, social engineering, impersonation, or cyber threats. "
            "Evaluate scam likelihood (0-100), identify threat category, extract psychological manipulation tactics, "
            "highlight suspicious requests, provide a plain-English explanation, and advise safe actions. "
            "Be precise, objective, and avoid false positives on legitimate transaction alerts."
        )

        user_prompt = f"Analyze this user message for cybersecurity and digital safety threats:\n\n---\n{message}\n---"
        if context:
            user_prompt += (
                f"\n\nContextual signals detected by rule engine: "
                f"Rule Score: {context.get('score', 0)}/100, Warnings: {context.get('warnings', [])}"
            )

        try:
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=GeminiScamAnalysis,
                temperature=0.2,
            )

            # Try primary model, with resilient fallbacks if high demand or deprecation occurs
            candidate_models = [self.model_name]
            for fallback in ["gemini-3-flash-preview", "gemini-flash-latest", "gemini-3.5-flash"]:
                if fallback not in candidate_models:
                    candidate_models.append(fallback)

            response = None
            used_model = self.model_name
            for model_to_try in candidate_models:
                try:
                    res = self.client.models.generate_content(
                        model=model_to_try,
                        contents=user_prompt,
                        config=config,
                    )
                    if res and res.text:
                        response = res
                        used_model = model_to_try
                        break
                except Exception:
                    continue

            if not response or not response.text:
                return None

            raw_text = response.text
            data = json.loads(raw_text)

            score = int(data.get("scam_likelihood_score", 0))
            score = max(0, min(100, score))

            risk_level = data.get("risk_level", "LOW RISK")
            if risk_level not in ["HIGH RISK", "MEDIUM RISK", "LOW RISK"]:
                risk_level = "HIGH RISK" if score >= 60 else ("MEDIUM RISK" if score >= 30 else "LOW RISK")

            return {
                "scam_likelihood_score": score,
                "risk_level": risk_level,
                "primary_category": data.get("primary_category", "Unclassified Threat"),
                "detected_categories": data.get("detected_categories", []),
                "psychological_tactics": data.get("psychological_tactics", []),
                "suspicious_requests": data.get("suspicious_requests", []),
                "plain_english_explanation": data.get("plain_english_explanation", ""),
                "recommended_actions": data.get("recommended_actions", []),
                "model_name": used_model
            }

        except Exception:
            # Mask and avoid exposing any API key or internal exception details
            return None


class RuleBasedAnalyzer:
    """Core heuristic, keyword, regex, taxonomy, and psychological red-flag analyzer."""

    def __init__(self):
        # Scam keywords with weights (preserved from Phase 1)
        self.scam_words = [
            "won", "winner", "prize", "lottery",
            "urgent", "immediately", "claim",
            "free", "reward", "congratulations"
        ]

        # Sensitive credential requests with weights (preserved from Phase 1)
        self.sensitive_words = [
            "otp", "password", "pin",
            "bank details", "credit card",
            "debit card", "cvv"
        ]

        # URL and shortener patterns (preserved from Phase 1)
        self.url_pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|org|net|in|co|xyz|top|info|biz|live|site|online|app|vip)[/\w.-]*)"
        self.shortener_pattern = r"\b(?:bit\.ly|tinyurl\.com|t\.me|is\.gd|cutt\.ly|rb\.gy|wa\.me)\/[^\s]+"

        # Urgency triggers
        self.urgency_phrases = ["click now", "act now"]

        # Scam Taxonomy / Category Mappings
        self.categories_map = {
            "Banking & Financial Fraud": [
                "bank", "account blocked", "suspended", "kyc", "pan card", "aadhaar",
                "netbanking", "credit card", "debit card", "cvv", "otp", "atm", "sbi",
                "hdfc", "icici", "pnb", "unauthorized transaction", "beneficiary", "update pan"
            ],
            "Lottery & Prize Scam": [
                "lottery", "won", "winner", "prize", "lucky draw", "reward", "jackpot",
                "kbc", "cash prize", "congratulations", "claim prize"
            ],
            "Part-Time Job & Task Scam": [
                "part-time", "part time", "work from home", "earn daily", "daily income",
                "like videos", "subscribe youtube", "task", "telegram", "earn ₹", "earn rs",
                "daily payout", "salary"
            ],
            "Law Enforcement & Digital Arrest": [
                "police", "customs", "narcotics", "arrest", "digital arrest", "cbi",
                "crime branch", "illegal parcel", "warrant", "court order", "cyber crime department"
            ],
            "Delivery & Courier Phishing": [
                "parcel", "courier", "package", "india post", "fedex", "dhl", "bluedart",
                "undelivered", "wrong address", "incomplete address", "redelivery"
            ]
        }

        # Psychological Manipulation / Red-Flag Indicators
        self.manipulation_map = {
            "Artificial Urgency": {
                "keywords": ["urgent", "immediately", "click now", "act now", "within 24 hours", "expires today", "today only", "right now", "last chance"],
                "description": "Creates panic and time pressure to bypass critical thinking."
            },
            "Fear & Coercion": {
                "keywords": ["blocked", "suspended", "arrest", "legal action", "police", "penalty", "warrant", "deactivated", "law enforcement", "fine"],
                "description": "Uses intimidation and threats of punishment or loss."
            },
            "Greed & Unrealistic Reward": {
                "keywords": ["won", "winner", "prize", "lottery", "reward", "free", "guaranteed return", "daily income", "cash prize"],
                "description": "Baits victims with unearned money or unrealistic financial promises."
            },
            "Authority Impersonation": {
                "keywords": ["police", "customs", "cbi", "bank", "rbi", "income tax", "department", "inspector", "india post"],
                "description": "Poses as respected institutions or law enforcement to demand compliance."
            },
            "Credential Harvesting": {
                "keywords": ["otp", "password", "pin", "cvv", "bank details", "credit card", "debit card"],
                "description": "Explicitly requests private authentication or banking secrets."
            }
        }

    def analyze(self, message: str) -> Dict[str, Any]:
        score = 0
        warnings = []

        # 1. Scam-related keywords (matched with word boundaries)
        for word in self.scam_words:
            pattern = rf"\b{re.escape(word)}\b"
            if re.search(pattern, message, re.IGNORECASE):
                score += 10
                warnings.append(f"Suspicious word detected: '{word}'")

        # 2. Sensitive information (matched with word boundaries)
        for word in self.sensitive_words:
            pattern = rf"\b{re.escape(word)}\b"
            if re.search(pattern, message, re.IGNORECASE):
                score += 20
                warnings.append(f"Request for sensitive information: '{word}'")

        # 3. Links (standard URLs, naked domains, and common shorteners)
        has_shortener = bool(re.search(self.shortener_pattern, message, re.IGNORECASE))
        has_url = bool(re.search(self.url_pattern, message, re.IGNORECASE))

        if has_shortener:
            score += 20
            warnings.append("Message contains a suspicious shortened link")
        elif has_url:
            score += 20
            warnings.append("Message contains a link")

        # 4. Urgency (matched with word boundaries)
        for phrase in self.urgency_phrases:
            pattern = rf"\b{re.escape(phrase)}\b"
            if re.search(pattern, message, re.IGNORECASE):
                score += 20
                warnings.append("Creates a sense of urgency")
                break

        # Limit score (0 - 100)
        score = min(score, 100)

        # Risk level & styling class (preserved from Phase 1)
        if score >= 60:
            risk = "HIGH RISK"
            risk_class = "high"
            recommendation = "Do not click links or share personal/banking information."
        elif score >= 30:
            risk = "MEDIUM RISK"
            risk_class = "medium"
            recommendation = "Be careful. Verify the sender before taking any action."
        else:
            risk = "LOW RISK"
            risk_class = "low"
            recommendation = "No major scam indicators were detected, but stay cautious."

        if not warnings:
            warnings.append("No obvious scam indicators detected.")

        # 5. Detect Scam Categories
        detected_categories = []
        for cat_name, kw_list in self.categories_map.items():
            for kw in kw_list:
                pattern = rf"\b{re.escape(kw)}\b"
                if re.search(pattern, message, re.IGNORECASE):
                    detected_categories.append(cat_name)
                    break

        if not detected_categories:
            if score >= 30 and (has_shortener or has_url):
                detected_categories.append("Phishing & Malicious Link")
            elif score >= 30:
                detected_categories.append("Suspicious / Unclassified Threat")
            else:
                detected_categories.append("Legitimate / Low Suspicion")

        # 6. Detect Psychological Manipulation Tactics
        detected_tactics = []
        for tactic_name, tactic_data in self.manipulation_map.items():
            matched_kws = []
            for kw in tactic_data["keywords"]:
                pattern = rf"\b{re.escape(kw)}\b"
                if re.search(pattern, message, re.IGNORECASE):
                    matched_kws.append(kw)
            if matched_kws:
                detected_tactics.append({
                    "name": tactic_name,
                    "description": tactic_data["description"],
                    "matched": matched_kws[:3]
                })

        # 7. Action Steps Checklist
        action_steps = []
        if risk_class == "high":
            action_steps.append("DO NOT click any link, scan QR codes, or download attachments.")
            action_steps.append("NEVER share OTP, UPI PIN, ATM PIN, or passwords with anyone claiming to be an official.")
            action_steps.append("If you already shared banking details, immediately freeze your account or block cards via your mobile banking app.")
            action_steps.append("Block the sender and report the number/message immediately.")
        elif risk_class == "medium":
            action_steps.append("Cross-verify the message via the organization's official website or customer care number.")
            action_steps.append("Do not use phone numbers or links provided inside this suspicious message.")
            action_steps.append("Check the sender ID or email address carefully for subtle spelling errors or strange domains.")
        else:
            action_steps.append("Message appears benign, but remain vigilant against unexpected requests.")
            action_steps.append("Remember that legitimate banks and government agencies never ask for OTPs or PINs via SMS/chat.")

        # 8. India Cyber-Safety & Official Reporting Guidance
        india_reporting = {
            "helpline": "1930",
            "helpline_desc": "National Cyber Crime Reporting Toll-Free Helpline (Citizen Financial Cyber Fraud Reporting)",
            "portal_url": "https://cybercrime.gov.in",
            "portal_name": "cybercrime.gov.in (National Cyber Crime Reporting Portal)",
            "chakshu_url": "https://sancharsaathi.gov.in",
            "chakshu_name": "Sanchar Saathi / Chakshu (DoT Fraud Communication Reporting)",
            "rbi_advisory": "Report unauthorized transactions within 24-72 hours to minimize or eliminate financial liability under RBI guidelines."
        }

        return {
            "risk": risk,
            "score": score,
            "warnings": warnings,
            "recommendation": recommendation,
            "risk_class": risk_class,
            "categories": detected_categories,
            "tactics": detected_tactics,
            "action_steps": action_steps,
            "india_reporting": india_reporting
        }


class ScamShieldEngine:
    """Unified engine coordinating Heuristic Layer and Google Gemini AI Layer."""

    def __init__(self, ai_provider: Optional[BaseAIEngine] = None):
        self.rule_engine = RuleBasedAnalyzer()
        self.ai_provider = ai_provider if ai_provider is not None else GeminiAIEngine()

    def analyze(self, message: str) -> Dict[str, Any]:
        # 1. Run deterministic Rule-based Heuristic Layer first (Guaranteed baseline)
        rule_result = self.rule_engine.analyze(message)

        # 2. Run Gemini AI Layer if available
        ai_data = None
        if self.ai_provider and self.ai_provider.is_available():
            ai_data = self.ai_provider.analyze(message, context=rule_result)

        # 3. If AI is not available or call failed, return rule result in Rule Engine mode
        if not ai_data:
            rule_result["ai_active"] = False
            rule_result["ai_status"] = "Rule Engine Mode (Deterministic)"
            rule_result["ai_explanation"] = ""
            rule_result["suspicious_requests"] = []
            return rule_result

        # 4. Hybrid Signal Blending
        rule_score = rule_result["score"]
        ai_score = ai_data["scam_likelihood_score"]
        blended_score = max(rule_score, ai_score)

        if blended_score >= 60:
            risk = "HIGH RISK"
            risk_class = "high"
        elif blended_score >= 30:
            risk = "MEDIUM RISK"
            risk_class = "medium"
        else:
            risk = "LOW RISK"
            risk_class = "low"

        # Merge Categories (Rule + AI)
        merged_categories = list(rule_result.get("categories", []))
        for cat in ai_data.get("detected_categories", []):
            if cat and cat not in merged_categories:
                merged_categories.append(cat)
        if any(c for c in merged_categories if "Legitimate" not in c and "Low" not in c):
            merged_categories = [c for c in merged_categories if "Legitimate" not in c]

        # Merge Psychological Tactics
        merged_tactics = list(rule_result.get("tactics", []))
        existing_tactic_names = {t["name"].lower() for t in merged_tactics}
        for ai_tactic in ai_data.get("psychological_tactics", []):
            t_name = ai_tactic.get("name", "") if isinstance(ai_tactic, dict) else getattr(ai_tactic, "name", "")
            t_desc = ai_tactic.get("explanation", "") if isinstance(ai_tactic, dict) else getattr(ai_tactic, "explanation", "")
            if t_name and t_name.lower() not in existing_tactic_names:
                merged_tactics.append({
                    "name": t_name,
                    "description": t_desc,
                    "matched": ["AI Semantic Context"]
                })
                existing_tactic_names.add(t_name.lower())

        # Merge Action Steps
        merged_action_steps = list(rule_result.get("action_steps", []))
        for rec in ai_data.get("recommended_actions", []):
            if rec and rec not in merged_action_steps:
                merged_action_steps.append(rec)

        return {
            "risk": risk,
            "score": blended_score,
            "warnings": rule_result["warnings"],
            "recommendation": rule_result["recommendation"],
            "risk_class": risk_class,
            "categories": merged_categories,
            "tactics": merged_tactics,
            "action_steps": merged_action_steps,
            "india_reporting": rule_result["india_reporting"],
            "ai_active": True,
            "ai_status": f"Google Gemini Semantic Analysis Active ({ai_data.get('model_name', 'Gemini')})",
            "ai_explanation": ai_data.get("plain_english_explanation", ""),
            "suspicious_requests": ai_data.get("suspicious_requests", []),
            "ai_model": ai_data.get("model_name", "Gemini")
        }

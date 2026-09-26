from typing import Dict, Any

# Dictionary of Template Mappings for Bilingual English & Hindi Security Alerts
VERNACULAR_TEMPLATES = {
    "DRIFT_CRITICAL": {
        "en": "Critical drift detected in model {model_name}. Feature '{feature}' shifted {ratio}x (PSI: {psi}). Potential data poisoning attack.",
        "hi": "गंभीर विचलन चेतावनी: मॉडल {model_name} में फीचर '{feature}' सामान्य से {ratio} गुना बदल गया है (PSI: {psi})। संभावित डेटा पॉइज़निंग हमला।",
        "hinglish": "Gambhir drift chetavani: Model {model_name} mein feature '{feature}' {ratio} guna badal gaya hai. Sambhavit data poisoning hamla.",
        "voice": "Chetavani! AI Model {model_name} par data poisoning hamla detect hua hai. Feature {feature} aniyamit hai."
    },
    "DRIFT_WARNING": {
        "en": "Moderate drift detected in {model_name}. Feature '{feature}' PSI is {psi}. Tightening confidence throttling.",
        "hi": "मध्यम विचलन चेतावनी: {model_name} में फीचर '{feature}' का PSI {psi} है। लेन-देन थ्रॉटलिंग नियम कड़े किए जा रहे हैं।",
        "hinglish": "Madhyam drift chetavani: {model_name} mein feature '{feature}' badal raha hai. Confidence throttling badhayi gayi hai.",
        "voice": "Dhyan dein. Model {model_name} mein madhyam drift paaya gaya hai. Confidence rules tight kiye gaye hain."
    },
    "QUARANTINE_ROLLBACK": {
        "en": "EMERGENCY: Model {model_name} quarantined (Trust Score: {score}/100). Live traffic successfully rolled back to verified safe checkpoint.",
        "hi": "आपातकालीन सुरक्षा: मॉडल {model_name} को क्वारंटीन किया गया (ट्रस्ट स्कोर: {score}/100)। ट्रैफिक को सुरक्षित चेकपॉइंट पर रोलबैक कर दिया गया है।",
        "hinglish": "Aapatkalin suraksha: Model {model_name} ko quarantine kiya gaya (Trust Score: {score}). Safe checkpoint par rollback safal.",
        "voice": "Suraksha Alert! Model {model_name} ko quarantine karke safe checkpoint par rollback kar diya gaya hai."
    },
    "HONEYPOT_DETECTED": {
        "en": "SECURITY BREACH ATTEMPT: Adversarial honeypot triggered by '{canary}'. Attacker probing detected.",
        "hi": "सुरक्षा उल्लंघन प्रयास: हनीपॉट ट्रिगर '{canary}' सक्रिय हुआ। हमलावर द्वारा मॉडल की टोह लेने की पुष्टि।",
        "hinglish": "Suraksha ullanghan prayas: Honeypot canary '{canary}' trigger hua. Attacker probing detect hui hai.",
        "voice": "Alert! Adversarial Honeypot trigger hua hai. Attacker probing detect hui."
    },
    "CREDENTIAL_LEAK_CORRELATED": {
        "en": "THREAT INTEL MATCH: Attack vectors correlate with '{source}' dark web breach feed.",
        "hi": "डार्क वेब थ्रेट इंटेलिजेंस मैच: हमले के पैटर्न '{source}' डेटा लीक से मेल खाते हैं।",
        "hinglish": "Dark web threat match: Hamle ke patterns '{source}' data breach se match kar rahe hain.",
        "voice": "Threat intelligence alert! Hamla dark web leaked credentials se correlate ho raha hai."
    },
    "THROTTLING_ACTIVE": {
        "en": "Confidence Throttling Active: Auto-approval threshold increased to {threshold}% due to Trust Score degradation ({score}).",
        "hi": "कॉन्फिडेंस थ्रॉटलिंग सक्रिय: ट्रस्ट स्कोर ({score}) घटने के कारण ऑटो-स्वीकृति सीमा बढ़ाकर {threshold}% कर दी गई है।",
        "hinglish": "Confidence Throttling sakriya: Trust score {score} hone par auto-approval limit {threshold}% kar di gayi hai.",
        "voice": "Confidence throttling sakriya hai. Transaction verification rules ko tight kar diya gaya hai."
    },
    "SYSTEM_HEALTHY": {
        "en": "Model {model_name} integrity verified. Trust Score: {score}/100. System operational and safe.",
        "hi": "मॉडल {model_name} की अखंडता सत्यापित। ट्रस्ट स्कोर: {score}/100। सिस्टम पूरी तरह सुरक्षित और सामान्य है।",
        "hinglish": "Model {model_name} bilkul surakshit hai. Trust score: {score}. System theek kaam kar raha hai.",
        "voice": "Model {model_name} surakshit hai aur normal operate kar raha hai."
    }
}

def translate_alert(template_key: str, context: Dict[str, Any]) -> Dict[str, str]:
    """
    Renders English, Hindi (Devanagari), Hinglish (Romanized), and Voice speech strings
    for a given alert context.
    """
    tmpl = VERNACULAR_TEMPLATES.get(template_key, VERNACULAR_TEMPLATES["SYSTEM_HEALTHY"])
    
    # Safe format with fallback
    def safe_format(template_str: str) -> str:
        try:
            return template_str.format(**context)
        except Exception:
            return template_str

    return {
        "english": safe_format(tmpl["en"]),
        "hindi": safe_format(tmpl["hi"]),
        "hinglish": safe_format(tmpl["hinglish"]),
        "voice_script": safe_format(tmpl["voice"])
    }

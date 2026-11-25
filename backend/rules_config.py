"""Centralized scoring thresholds, rule weights, keyword lexicons, and URL heuristic tables.

Keeping thresholds, weights, and curated Arabic/English phrase lists in one documented
module prevents drift across analyzers and makes scoring behavior easy to audit.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Message Analyzer Thresholds, Category Priorities & Keyword Lists
# ---------------------------------------------------------------------------

DEFAULT_MESSAGE_THRESHOLDS: dict[str, int] = {
    "suspicious_threshold": 30,
    "dangerous_threshold": 65,
}

MESSAGE_CATEGORY_PRIORITY: list[str] = [
    "otp_theft",
    "fake_prize",
    "fake_delivery",
    "investment_fraud",
    "fake_job",
    "phishing_bank",
]

MESSAGE_RULE_POINTS: dict[str, int] = {
    "custom_domain_blocklist": 55,
    "brand_impersonation": 35,
    "raw_ip_url": 25,
    "punycode_or_homograph": 25,
    "open_redirect_lure": 25,
    "shortened_url": 15,
    "suspicious_tld": 15,
    "excessive_subdomains_or_at": 15,
    "no_https": 5,
    "sensitive_data": 35,
    "money_transfer_giftcard": 25,
    "coercive_urgency": 20,
    "soft_urgency": 15,
    "direct_prize": 25,
    "weak_prize": 20,
    "fake_delivery": 20,
    "fake_job_investment": 25,
    "oauth_consent_phishing": 35,
    "subtle_social_engineering": 30,
    "authority_impersonation_link": 20,
    "excessive_formatting": 5,
    "text_obfuscation": 15,
}

BENIGN_CONTEXT_DAMPENER = 20
LOW_SIGNAL_DAMPENER = 10

ACTION_LURE_PHRASES: list[str] = [
    "اضغط الرابط",
    "افتح الرابط",
    "انقر هنا",
    "ادخل الرابط",
    "سجل عبر",
    "سجل بالرابط",
    "حدث بياناتك",
    "اكد معلوماتك",
    "تحديث بيانات",
    "تحديث الحساب",
    "دزلي",
    "ارسل الرمز",
    "click the link",
    "click here",
    "open the link",
    "verify via",
    "update your account",
    "confirm your details",
    "fill out the form",
    "submit below",
]

BENIGN_CONTEXT_PHRASES: list[str] = [
    "الدخول مجاني",
    "الحضور مجاني",
    "مجاناً للطلبة",
    "مجانا للطلبة",
    "ندوة علمية",
    "ورشة عمل",
    "قاعة المؤتمرات",
    "اجتماع القسم",
    "التفوق العلمي",
    "جائزة التفوق",
    "حصلت الطالبة",
    "حصل الطالب",
    "بريد الجامعة الرسمي",
    "البريد الرسمي للشركة",
    "free admission",
    "free entry",
    "academic award",
    "meeting reminder",
    "conference room",
    "monthly report",
]

NO_SHARE_ADVISORY_PHRASES: list[str] = [
    "لا تشارك هذا الرمز",
    "لا تشارك الرمز",
    "عدم مشاركه الرمز",
    "do not share this code",
    "never share this code",
    "do not share your code",
]

SENSITIVE_CREDENTIAL_PHRASES: list[str] = [
    "otp",
    "cvv",
    "pin",
    "رمز التحقق",
    "كود التحقق",
    "رمز التاكيد",
    "كود التفعيل",
    "دزيت رمز الـ 6 ارقام",
    "رمز الـ 6 ارقام",
    "دزلي الرمز",
    "دز الرمز",
    "دز الكود",
    "ارسل الرمز",
    "وصلتك رسالة بيها رقم",
    "كلمه المرور",
    "كلمه السر",
    "الرقم السري",
    "رقم البطاقه",
    "بيانات البطاقه",
    "معلومات البطاقه",
    "تاريخ الانتهاء",
    "بيانات الدخول",
    "ملف .env",
    "مفتاح api",
    "verification code",
    "whatsapp verification code",
    "send me the code",
    "upload your .env",
    "api key",
    "password",
    "passcode",
    "card number",
    "security code",
    "one time password",
    "login credentials",
]

TRANSFER_AND_FEE_PHRASES: list[str] = [
    "تحويل مبلغ",
    "حول مبلغ",
    "حول رصيد",
    "حول لي",
    "ارسال مبلغ",
    "دفع رسوم",
    "رسوم نشر عاجله",
    "بطاقه هدايا",
    "بطاقات هدايا",
    "كرت شحن",
    "كارت رصيد",
    "ارسل رصيد",
    "حواله ماليه",
    "غيرنا حساب التحويل",
    "تغيير رقم الحساب البنكي",
    "تحديث بيانات الفاتوره",
    "transfer money",
    "wire transfer",
    "wire funds",
    "send money",
    "urgent publication fee",
    "gift card",
    "gift cards",
    "itunes card",
    "steam card",
    "routing changed",
    "updated bank account",
    "updated invoice",
]

COERCIVE_URGENCY_PHRASES: list[str] = [
    "سيتم ايقاف حسابك",
    "سيتم تعليق حسابك",
    "سيتم حظر حسابك",
    "تم تجميد حسابك",
    "تم تجميد محفظتك",
    "تجميد محفظتك",
    "ايقاف محفظتك",
    "حسابك راح ينسد",
    "حسابك سينغلق",
    "اخر تحذير",
    "تنبيه اخير",
    "قبل انتهاء المهله",
    "account suspended",
    "will be suspended",
    "final warning",
    "last warning",
    "your account will be locked",
]

SOFT_URGENCY_PHRASES: list[str] = [
    "خلال 24 ساعه",
    "خلال ٢٤ ساعه",
    "خلال ساعات",
    "فورا",
    "عاجل جدا",
    "عاجل",
    "act now",
    "within 24 hours",
    "immediately",
    "urgent action",
    "before end of day",
]

DIRECT_PRIZE_SCAM_PHRASES: list[str] = [
    "مبروك ربحت",
    "مبروك فزت",
    "لقد ربحت",
    "دخلت السحب",
    "فائز في السحب",
    "سحب عشوائي",
    "لاستلام الجائزه",
    "استلم جائزتك",
    "منحه ماليه فوريه",
    "عرض مجاني محدود",
    "you won",
    "you have won",
    "congratulations you won",
    "claim your prize",
    "lucky winner",
    "selected as a winner",
]

WEAK_PRIZE_WORDS: list[str] = [
    "ربحت",
    "جائزه",
    "جائزه نقديه",
    "جائزه ماليه",
    "مجاني",
    "مجانا",
    "cash prize",
    "free gift",
]

DELIVERY_PHRASES: list[str] = [
    "طردك",
    "شحنتك",
    "رسوم جمركيه",
    "تعذر التسليم",
    "تعذر توصيل",
    "اعاده جدوله التوصيل",
    "توصيل الطرد",
    "البريد العراقي",
    "customs fee",
    "delivery failed",
    "your package",
    "your parcel",
    "shipping fee",
    "unable to deliver",
]

JOB_PHRASES: list[str] = [
    "رسوم تسجيل للوظيفه",
    "رسوم توظيف",
    "تعيين فوري",
    "العمل من المنزل براتب",
    "توظيف فوري",
    "job fee",
    "registration fee",
    "hiring fee",
    "work from home earn",
]

INVESTMENT_PHRASES: list[str] = [
    "ربح يومي مضمون",
    "دخل يومي مضمون",
    "ارباح مضمونه",
    "استثمار مضمون",
    "تداول مضمون",
    "مضاعفه راس المال",
    "اربح يوميا",
    "guaranteed daily profit",
    "guaranteed return",
    "guaranteed profit",
    "double your money",
]

OAUTH_CONSENT_PHRASES: list[str] = [
    "صلاحيه قراءه وارسال",
    "منح تطبيق المساعد صلاحيه",
    "permission to read and send",
    "read and send your gmail",
    "granting our assistant app permission",
]

SUBTLE_SE_PHRASES: list[str] = [
    "الدعم التقني",
    "فريق تقنيه المعلومات",
    "عدم مزامنه بريدك",
    "مزامنه بريدك",
    "مزامنه الحساب",
    "تفعيل البوابه البديله",
    "البوابه البديله",
    "استمرار خدمتك",
    "اعاده التحقق من هويتك",
    "تحديث البوابه",
    "تحديث بيانات البطاقه الوطنيه",
    "منحه الرعايه الاجتماعيه",
    "it support team",
    "helpdesk",
    "mailbox sync",
    "alternate portal",
    "confirm your access",
    "re-validate your profile",
    "vendor payment details",
    "audit review",
    "updated invoice",
    "new settlement account",
    "settlement account",
    "updated bank account",
    "routing changed",
    "new bank details",
    "غيرنا حساب التحويل",
    "تغيير رقم الحساب البنكي",
    "تحديث بيانات الفاتوره",
    "الحساب الجديد",
]

AUTHORITY_PHRASES: list[str] = [
    "المصرف",
    "مصرف الرافدين",
    "مصرف الرشيد",
    "البنك المركزي",
    "البنك",
    "زين كاش",
    "كي كارد",
    "اسياسيل",
    "شركه زين",
    "كورك",
    "الشرطه",
    "مديريه المرور",
    "وزاره الداخليه",
    "وزاره الماليه",
    "الوزاره",
    "الضرائب",
    "الحكومه",
    "خدمه العملاء",
    "bank",
    "central bank",
    "telecom",
    "police",
    "ministry",
    "tax authority",
    "government",
    "customer support",
]


# ---------------------------------------------------------------------------
# URL Forensic Rules, Tracking / Query Sets & Homograph Map
# ---------------------------------------------------------------------------

TRACKING_PARAMS: set[str] = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "yclid",
    "mc_cid",
    "mc_eid",
    "igshid",
    "si",
    "spm",
}

SUSPICIOUS_QUERY_KEYS: set[str] = {
    "redirect",
    "redirect_uri",
    "next",
    "return",
    "return_url",
    "url",
    "target",
    "dest",
    "token",
    "otp",
    "pin",
    "cvv",
    "password",
    "session",
    "auth",
    "verify",
    "login",
}

SUSPICIOUS_TLDS: set[str] = {
    ".xyz",
    ".top",
    ".click",
    ".icu",
    ".tk",
    ".gq",
    ".work",
    ".live",
    ".cf",
    ".ml",
    ".ga",
    ".buzz",
    ".cam",
    ".monster",
    ".cfd",
    ".sbs",
    ".zip",
}

SHORTENER_DOMAINS: set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "ow.ly",
    "shorturl.at",
    "rebrand.ly",
    "t.ly",
    "goo.gl",
    "buff.ly",
}

# Confusable non-Latin characters commonly abused in IDN homograph attacks
CONFUSABLE_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u03bf": "o",  # Greek omicron
    "\u03b1": "a",  # Greek alpha
    "\u03b5": "e",  # Greek epsilon
    "\u03c1": "p",  # Greek rho
    "\u03ba": "k",  # Greek kappa
}

URL_FORENSIC_WEIGHTS: dict[str, int] = {
    "custom_blocklisted": 55,
    "brand_impersonation": 35,
    "raw_ip": 25,
    "mixed_script_homograph": 30,
    "punycode": 20,
    "shortener": 15,
    "suspicious_tld": 15,
    "deceptive_structure": 15,
    "high_entropy": 10,
    "embedded_redirect_param": 20,
    "sensitive_query_param": 10,
    "http_unencrypted": 10,
}

URL_HIGH_ENTROPY_THRESHOLD = 3.7
URL_YOUNG_DOMAIN_DAYS = 30
URL_MALICIOUS_SCORE_THRESHOLD = 60
URL_SUSPICIOUS_SCORE_THRESHOLD = 15


# ---------------------------------------------------------------------------
# Academic Integrity & AI Stylometry Rules
# ---------------------------------------------------------------------------

MIN_AI_CALIBRATION_WORDS = 35
AI_UNCERTAINTY_BAND = (0.35, 0.65)
AI_CONFLICT_UNCERTAINTY_BAND = (0.25, 0.78)

PLAGIARISM_WEIGHT = 0.65
AI_PROBABILITY_WEIGHT = 0.35
PLAGIARISM_MATCH_MIN_PCT = 5
CERT_MIN_ORIGINALITY_SCORE = 70
CERT_MIN_WORD_COUNT = 15
CERT_MAX_PLAGIARISM_PCT = 15

AI_DISCOURSE_AR: list[str] = [
    "مما لا شك فيه",
    "علاوة على ذلك",
    "في الختام",
    "تجدر الاشاره الي",
    "بناء علي ما سبق",
    "من ناحيه اخري",
    "يلعب دورا حيويا",
    "في عصرنا الحالي",
    "لا يمكن اغفال",
    "بشكل عام يمكن القول",
    "في نهايه المطاف",
    "تعد من اهم الركائز",
    "وبالاضافه الي ذلك",
    "ومن جهه اخري",
    "وختاما",
    "في هذا السياق",
    "وعليه فان",
    "ومن ثم",
]

AI_DISCOURSE_EN: list[str] = [
    "moreover",
    "furthermore",
    "in conclusion",
    "it is worth noting",
    "delve into",
    "comprehensive overview",
    "plays a crucial role",
    "in today's rapidly evolving",
    "on the other hand",
    "undoubtedly",
    "testament to",
    "landscape of",
    "in summary",
    "ultimately",
    "taken together",
    "consequently",
    "nevertheless",
    "serves as a foundational",
]

PERSONAL_VOICE_AR: list[str] = [
    "انا",
    "نحن",
    "واجبنا",
    "واجهنا",
    "اكتشفنا",
    "اعتقد",
    "بصراحه",
    "بالامس",
    "عندما",
    "ظننا",
    "اضطررنا",
    "لماذا",
]

PERSONAL_VOICE_EN: list[str] = [
    "i ",
    "we ",
    "our ",
    "my ",
    "honestly",
    "yesterday",
    "bug",
    "weird",
    "why ",
    "messy",
]

THREAT_TYPE_LABELS: dict[str, dict[str, str]] = {
    "otp_credential_theft": {
        "ar": "سرقة رمز التحقق أو بيانات سرية",
        "en": "OTP / Credential Theft",
    },
    "fake_authority_impersonation": {
        "ar": "انتحال جهة رسمية أو علامة معروفة",
        "en": "Authority / Brand Impersonation",
    },
    "suspicious_link": {
        "ar": "رابط مشبوه",
        "en": "Suspicious Link",
    },
    "financial_fraud": {
        "ar": "احتيال مالي أو تحويل أموال",
        "en": "Financial Fraud",
    },
    "urgency_pressure": {
        "ar": "ضغط زمني واستعجال",
        "en": "Urgency & Pressure",
    },
    "fake_offer_prize": {
        "ar": "إغراء بجائزة أو عرض وهمي",
        "en": "Fake Prize / Offer",
    },
    "social_engineering": {
        "ar": "هندسة اجتماعية",
        "en": "Social Engineering",
    },
    "filter_evasion": {
        "ar": "تمويه لتجاوز الفلاتر",
        "en": "Filter Evasion",
    },
}


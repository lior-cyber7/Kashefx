"""Strictly held-out evaluation datasets for URL, Message Phishing, and AI Detection benchmarks.

Zero overlap with `ai_training_corpus.py` or `test_analyzer.py`.
"""

from __future__ import annotations

from typing import TypedDict


class UrlEvalCase(TypedDict):
    url: str
    category: str  # clean | phishing | malicious | unseen_new | shortener | idn_punycode
    is_threat: bool  # True if malicious/suspicious risk, False if clean/unseen benign


class MessageEvalCase(TypedDict):
    text: str
    category: str  # scam | normal | official_notice | iraqi | msa | english | subtle_se
    is_scam: bool


class AiEvalCase(TypedDict):
    text: str
    category: str  # human_ar | human_en | ai_ar | ai_en | hybrid_human_edited_ai | hybrid_ai_edited_human
    expected_origin: str  # "human" | "ai" | "hybrid"


URL_EVAL_SET: list[UrlEvalCase] = [
    # Known clean official
    {"url": "https://www.paypal.com/us/home", "category": "clean", "is_threat": False},
    {"url": "https://accounts.google.com/ServiceLogin", "category": "clean", "is_threat": False},
    {"url": "https://www.apple.com/support/", "category": "clean", "is_threat": False},
    {"url": "https://iq.zain.com/en/personal", "category": "clean", "is_threat": False},
    # Known phishing
    {"url": "http://paypa1-account-verify.xyz/signin", "category": "phishing", "is_threat": True},
    {"url": "https://zainca5h-billing.top/otp", "category": "phishing", "is_threat": True},
    {"url": "https://rafidain-online-verify.click/card", "category": "phishing", "is_threat": True},
    {"url": "https://apple-support.login-check.icu/reset", "category": "phishing", "is_threat": True},
    # Documented malicious patterns (raw IP, executable scheme, suspicious payload)
    {"url": "http://185.220.101.4/update/payload", "category": "malicious", "is_threat": True},
    {"url": "javascript:alert(document.cookie)", "category": "malicious", "is_threat": True},
    {"url": "http://login.bank.security.verify-portal.work/auth?redirect=https://evil.top", "category": "malicious", "is_threat": True},
    # Brand-new unseen neutral domains (must NOT trigger false positives)
    {"url": "https://baghdad-archive-2026.org/articles", "category": "unseen_new", "is_threat": False},
    {"url": "https://mesopotamia-solar-lab.net/publications", "category": "unseen_new", "is_threat": False},
    # Shorteners (risk indicator / obscured target)
    {"url": "https://bit.ly/4x9DemoLink", "category": "shortener", "is_threat": True},
    {"url": "https://tinyurl.com/pkg-customs-iq", "category": "shortener", "is_threat": True},
    # IDN / Punycode / Homographs
    {"url": "https://p\u0430ypal.com/auth", "category": "idn_punycode", "is_threat": True},
    {"url": "https://xn--pypal-property.com/login", "category": "idn_punycode", "is_threat": True},
    {"url": "https://g\u043e\u043egle.com/verify", "category": "idn_punycode", "is_threat": True},
]

MESSAGE_EVAL_SET: list[MessageEvalCase] = [
    # Benign / Official notices (including trigger words used legitimately!)
    {
        "text": "الحضور مجاني لجميع طلبة كلية الهندسة في ندوة الأمن الرقمي يوم الثلاثاء الساعة العاشرة صباحاً.",
        "category": "official_notice",
        "is_scam": False,
    },
    {
        "text": "تعميم عاجل من قسم التسجيل: يرجى تسليم استمارة المباشرة ورقياً لدى سكرتارية القسم غداً.",
        "category": "official_notice",
        "is_scam": False,
    },
    {
        "text": "تهنئة رسمية: فازت طالبتنا مريم علي بجائزة أفضل بحث تخرج في مسابقة الجامعات العراقية.",
        "category": "official_notice",
        "is_scam": False,
    },
    {
        "text": "السلام عليكم شباب، محاضرة قواعد البيانات تأجلت للساعة 11 بالقاعة 3.",
        "category": "normal",
        "is_scam": False,
    },
    {
        "text": "Hi Dr. Omar, I attached the revised literature review PDF in our shared university email thread. Thanks!",
        "category": "english",
        "is_scam": False,
    },
    {
        "text": "Reminder: Your PayPal monthly statement is ready inside your official account at https://www.paypal.com/activity",
        "category": "english",
        "is_scam": False,
    },
    # Iraqi dialect & MSA & English scams
    {
        "text": "أخي حسابك في مصرف الرافدين راح ينسد، دزلي الرمز الوصلك برسالة حتى نحدث معلوماتك هسه http://rafidain-iq.xyz",
        "category": "iraqi",
        "is_scam": True,
    },
    {
        "text": "تهانينا! لقد ربحت جائزة نقدية 3000 دولار، اضغط الرابط الآن http://reward-claim.top وأرسل رمز التحقق OTP.",
        "category": "msa",
        "is_scam": True,
    },
    {
        "text": "شحنتك معلّقة في البريد العراقي، يرجى دفع رسوم جمركية بسيطة عبر bit.ly/iq-post-fee لتوصيل الطرد خلال 24 ساعة.",
        "category": "msa",
        "is_scam": True,
    },
    {
        "text": "URGENT: Your Apple iCloud account will be suspended! Confirm password and card number at http://app1e-verify.icu/login",
        "category": "english",
        "is_scam": True,
    },
    # Subtle / evasive scams WITHOUT noisy buzzwords ("OTP"/"prize"/"urgent")
    {
        "text": "مرحباً، معك فريق تقنية المعلومات في الجامعة. لاحظنا عدم مزامنة بريدك الإلكتروني، يرجى تأكيد الدخول عبر البوابة البديلة https://campus-mail-sync.xyz/access",
        "category": "subtle_se",
        "is_scam": True,
    },
    {
        "text": "Hello, this is vendor billing. Our bank account routing changed for this week's invoice; please send the transfer to our updated bank account listed at http://billing-portal-check.top",
        "category": "subtle_se",
        "is_scam": True,
    },
    {
        "text": "فرصة استثمارية متميزة: دخل يومي مضمون مع سحب فوري للأرباح، سجل الآن وأرسل بطاقة هدايا بقيمة 50$ عبر https://invest-fast.click",
        "category": "scam",
        "is_scam": True,
    },
]

AI_EVAL_SET: list[AiEvalCase] = [
    # Held-out Human Arabic (including formal academic prose & narrative)
    {
        "text": (
            "عند فحصنا لسجلات الدخول في بوابة الطلبة، تفاجأنا بوجود مئات المحاولات الفاشلة من عناوين متفرقة "
            "فجر يوم الأحد. هل كان هجوماً منسقاً؟ في الواقع تبين بعد التدقيق أن تحديثاً جديداً في تطبيق الجوال "
            "كان يعيد إرسال كلمة المرور القديمة تلقائياً كل دقيقتين! أصلحنا الخلل بسرعة، لكنه ذكرنا بأهمية مراقبة السجلات."
        ),
        "category": "human_ar",
        "expected_origin": "human",
    },
    {
        "text": (
            "تطرح أنظمة التحقق الآلي إشكالية منهجية في الدراسات اللغوية المقارنة؛ فكثيراً ما تتشابه التراكيب "
            "المصاغة بعناية أكاديمية مع مخرجات النماذج الإحصائية الحديثة. ولذلك نبّه باحثو النزاهة العلمية إلى "
            "عدم الاعتماد على مؤشر رقمي مجرد دون مراجعة المصادر الأولية ومناقشة الطالب في تفاصيل منهجه."
        ),
        "category": "human_ar",
        "expected_origin": "human",
    },
    # Held-out Human English
    {
        "text": (
            "Testing spam filters against real Iraqi dialect messages proved harder than we expected. Standard Arabic "
            "stemmers kept stripping meaningful prefixes or missing slang verbs like 'دزلي'! After failing twice on "
            "our Friday evaluation batch, we built an index-preserving normalizer so highlighted phrases still line up "
            "character-for-character inside the browser interface."
        ),
        "category": "human_en",
        "expected_origin": "human",
    },
    {
        "text": (
            "Network telemetry collected across campus dormitories rarely exhibits stationary packet intervals. "
            "Whenever final exam week arrives, video streaming surges past midnight while daytime SSH traffic drops "
            "to almost zero. Any anomaly detector calibrated solely on October baselines will inevitably fire false alarms "
            "unless thresholds adapt to the academic calendar."
        ),
        "category": "human_en",
        "expected_origin": "human",
    },
    # Held-out AI Arabic
    {
        "text": (
            "مما لا شك فيه أن تقنيات الحوسبة السحابية تلعب دوراً حيوياً في تطوير التعليم العالي في عصرنا الحالي. "
            "علاوة على ذلك، تسهم هذه المنصات في تمكين الباحثين من الوصول إلى الموارد الحاسوبية بمرونة عالية. "
            "من ناحية أخرى، تجدر الإشارة إلى ضرورة الالتزام بمعايير الأمن السيبراني لحماية البيانات الأكاديمية. "
            "في الختام، بناءً على ما سبق، تعد الشراكة التقنية من أهم الركائز لتحقيق التميز المؤسسي."
        ),
        "category": "ai_ar",
        "expected_origin": "ai",
    },
    {
        "text": (
            "يمثل التعليم الرقمي خطوة استراتيجية مهمة نحو تحديث المنظومة التربوية ومواكبة التحولات العالمية المتسارعة. "
            "وبالإضافة إلى ذلك، تتيح المنصات التفاعلية تعزيز مهارات التفكير النقدي والتعلم الذاتي لدى الطلبة. "
            "غير أنه لا يمكن إغفال التحديات المرتبطة بالفجوة الرقمية وضمان جودة المحتوى العلمي المقدم. "
            "في نهاية المطاف، يبقى التوازن بين التكنولوجيا والإشراف الأكاديمي عاملاً أساسياً لنجاح التجربة."
        ),
        "category": "ai_ar",
        "expected_origin": "ai",
    },
    # Held-out AI English
    {
        "text": (
            "Moreover, modern threat intelligence platforms play a crucial role in strengthening institutional resilience. "
            "Furthermore, it is worth noting that automated correlation pipelines allow security analysts to delve into "
            "emerging phishing campaigns efficiently. On the other hand, relying on static blocklists alone proves "
            "insufficient in today's rapidly evolving landscape. In conclusion, multi-layered defense remains essential."
        ),
        "category": "ai_en",
        "expected_origin": "ai",
    },
    {
        "text": (
            "Digital transformation initiatives offer substantial advantages for public sector organizations seeking "
            "greater operational transparency. By streamlining document workflows and automating routine verification, "
            "institutions can improve service delivery significantly. However, sustainable implementation requires "
            "continuous staff training and clear governance policies. Ultimately, technology achieves lasting impact "
            "when paired with thoughtful institutional leadership."
        ),
        "category": "ai_en",
        "expected_origin": "ai",
    },
    # Hybrid / Mixed cases (Human-edited AI & AI-edited Human)
    {
        "text": (
            "Moreover, modern threat intelligence plays a crucial role in today's rapidly evolving campus networks. "
            "Wait—honestly, when our lab tested this last Tuesday in Baghdad, the Python parser crashed on an "
            "unusual UTF-8 link! Why did it fail? Furthermore, it is worth noting that messy real-world inputs always "
            "surprise clean benchmark assumptions, so in conclusion we rewrote the validator."
        ),
        "category": "hybrid_ai_edited_human",
        "expected_origin": "hybrid",
    },
    {
        "text": (
            "We deployed our campus phishing scanner during orientation week and caught three spoofed login portals "
            "targeting first-year students. Furthermore, it is worth noting that educational awareness campaigns "
            "remain a cornerstone of digital resilience. On the other hand, my script still needed manual tuning "
            "whenever someone pasted broken WhatsApp timestamps!"
        ),
        "category": "hybrid_human_edited_ai",
        "expected_origin": "hybrid",
    },
]

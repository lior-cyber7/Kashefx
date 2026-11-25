"""Interactive 20-Scenario Phishing IQ Lab powered by the Kashf Python analyzer."""

from __future__ import annotations

from typing import Any, TypedDict

from analyzer import analyze_message


class QuizScenario(TypedDict):
    id: str
    channel: str
    sender: str
    text_ar: str
    text_en: str
    is_scam: bool
    explanation_ar: str
    explanation_en: str


SCENARIOS: list[QuizScenario] = [
    {
        "id": "rafidain-otp",
        "channel": "SMS",
        "sender": "Rafidain-Alert",
        "text_ar": "تنبيه عاجل من مصرف الرافدين: سيتم إيقاف بطاقتك خلال 24 ساعة. حدث بيانات البطاقة وأرسل رمز التحقق فوراً عبر http://rafidain-verify.xyz/auth",
        "text_en": "Rafidain Bank Urgent Alert: Your card will be suspended within 24 hours. Update card details and submit your OTP at http://rafidain-verify.xyz/auth",
        "is_scam": True,
        "explanation_ar": "انتحال واضح لمصرف الرافدين: النطاق ينتهي بـ .xyz غير الرسمي، ويستخدم التهديد بالإيقاف خلال 24 ساعة مع طلب رمز التحقق.",
        "explanation_en": "Impersonates Rafidain Bank on an unofficial .xyz domain, uses 24-hour suspension pressure, and asks for your OTP.",
    },
    {
        "id": "official-zaincash-receipt",
        "channel": "SMS",
        "sender": "ZainCash",
        "text_ar": "تم استلام حوالة بمبلغ 25,000 د.ع بنجاح في محفظتك. يمكنك مراجعة سجل العمليات من تطبيق زين كاش الرسمي أو عبر https://zaincash.iq",
        "text_en": "You received 25,000 IQD in your wallet. Review your transaction history inside the official ZainCash app or at https://zaincash.iq",
        "is_scam": False,
        "explanation_ar": "رسالة إشعار طبيعية: تشير إلى النطاق الرسمي الحقيقي (zaincash.iq) ولا تطلب أي رمز سري أو دفع رسوم أو ضغط عاجل.",
        "explanation_en": "Legitimate notification: uses the authentic official domain (zaincash.iq) and makes no urgent threats or OTP requests.",
    },
    {
        "id": "subdomain-illusion-paypal",
        "channel": "Email",
        "sender": "billing@paypal-notices.info",
        "text_ar": "تنبيه مراجعة الفوترة: يرجى تأكيد نشاط حسابك عبر البوابة https://paypal.com.verify-account-iq.info/session لتفادي تجميد الحساب.",
        "text_en": "Billing review notice: please confirm your account activity at https://paypal.com.verify-account-iq.info/session to avoid an account freeze.",
        "is_scam": True,
        "explanation_ar": "خدعة النطاقات الفرعية (Subdomain Trick): وجود paypal.com في البداية مجرد نطاق فرعي تمويهي، أما النطاق الفعلي الذي يملك الصفحة فهو verify-account-iq.info!",
        "explanation_en": "Subdomain deception: 'paypal.com' here is only a prefix subdomain—the actual registered host controlling the page is 'verify-account-iq.info'.",
    },
    {
        "id": "legit-edu-iq-deadline",
        "channel": "Email",
        "sender": "registrar@uotechnology.edu.iq",
        "text_ar": "تنبيه عمادة الكلية: يرجى من الطلبة تثبيت مواد الفصل الدراسي الثاني قبل انتهاء الموعد المحدد يوم الخميس عبر نظام التعليم الإلكتروني الرسمي https://lms.uotechnology.edu.iq/notices",
        "text_en": "College Registrar Notice: Students must confirm second-semester course registration before Thursday's deadline via the official portal https://lms.uotechnology.edu.iq/notices",
        "is_scam": False,
        "explanation_ar": "إشعار جامعي رسمي حقيقي: وجود موعد نهائي أو استعجال طبيعي على نطاق جامعي موثق (.edu.iq) دون طلب رمز OTP أو كلمة مرور أو تحويل مالي لا يُعد تصيداً.",
        "explanation_en": "Legitimate academic notice: real administrative deadlines on an official .edu.iq domain with zero OTP, password, or payment demands are not phishing.",
    },
    {
        "id": "parcel-customs",
        "channel": "WhatsApp",
        "sender": "+964 770 *** 991",
        "text_ar": "البريد العراقي: تعذر تسليم شحنتك لوجود رسوم جمركية بسيطة (2000 د.ع). ادفع الآن عبر bit.ly/3x9demo لتفادي إرجاع الطرد.",
        "text_en": "Iraqi Post: Delivery failed due to a small customs fee ($2). Pay immediately at bit.ly/3x9demo to avoid parcel return.",
        "is_scam": True,
        "explanation_ar": "حيلة شائعة جداً: استخدام رابط مختصر (bit.ly) لإخفاء الموقع الحقيقي وطلب رسوم رمزية لسرقة معلومات بطاقتك المصرفية.",
        "explanation_en": "Classic parcel scam: hides the destination behind a bit.ly shortener and asks for a tiny fee to harvest payment card details.",
    },
    {
        "id": "idn-homograph-apple",
        "channel": "SMS",
        "sender": "Apple-Support",
        "text_ar": "تم قفل معرف Apple الخاص بك مؤقتاً. أعد التحقق من بيانات الدخول عبر https://xn--pple-43d.com/support خلال 24 ساعة.",
        "text_en": "Your Apple ID has been temporarily locked. Re-verify your login credentials at https://xn--pple-43d.com/support within 24 hours.",
        "is_scam": True,
        "explanation_ar": "هجوم التماثل البصري (IDN Homograph / Punycode): البادئة xn-- تكشف استخدام حرف غير لاتيني يشبه الحرف اللاتيني في اسم علامة شهيرة لخداع العين.",
        "explanation_en": "IDN Homograph attack: the 'xn--' Punycode prefix reveals non-Latin lookalike characters masquerading as a trusted brand domain.",
    },
    {
        "id": "legit-2fa-no-link",
        "channel": "SMS",
        "sender": "SecurityCode",
        "text_ar": "رمز التحقق لمرة واحدة لتسجيل دخولك هو 482910. لا تشارك هذا الرمز مع أي شخص حتى لو ادعى أنه من الدعم الفني.",
        "text_en": "Your one-time verification code to sign in is 482910. Do not share this code with anyone, even if they claim to be technical support.",
        "is_scam": False,
        "explanation_ar": "إشعار تحقق ثنائي سليم (2FA): الرسالة ترسل لك رمزك مع تحذير صريح بعدم مشاركته، وتخلو تماماً من أي روابط أو طلب للرد أو الإرسال.",
        "explanation_en": "Authentic 2FA notification: delivers your requested code with an explicit warning never to share it and contains zero links or reply demands.",
    },
    {
        "id": "bec-it-mailbox-sync",
        "channel": "Email",
        "sender": "it-helpdesk@campus-mail.cfd",
        "text_ar": "فريق تقنية المعلومات: لم تكتمل مزامنة بريدك الإلكتروني بعد التحديث الليلي. لاستمرار خدمتك استخدم البوابة البديلة https://webmail-sync.cfd/sso وأكد كلمة المرور.",
        "text_en": "IT Support Team: Your mailbox sync failed after last night's update. To maintain access, use the alternate portal https://webmail-sync.cfd/sso and confirm your password.",
        "is_scam": True,
        "explanation_ar": "هندسة اجتماعية هادئة (BEC / IT Helpdesk Lure): صياغة إدارية مهذبة بدون كلمات إغراء صاخبة، لكنها تستدرجك إلى بوابة بديلة بنطاق .cfd لسرقة كلمة مرور البريد المؤسسي.",
        "explanation_en": "Subtle IT-support BEC lure: calm professional phrasing without flashy buzzwords, redirecting staff to an unofficial .cfd portal to harvest SSO passwords.",
    },
    {
        "id": "lookalike-paypal",
        "channel": "Email",
        "sender": "security@paypa1-support.com",
        "text_ar": "مبروك! ربحت 5000$ في السحب العشوائي! اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل كلمة المرور ورمز التحقق.",
        "text_en": "Congratulations! You won $5,000 in our lucky draw! Click within 24 hours http://paypa1-secure.xyz/login and confirm your password and OTP.",
        "is_scam": True,
        "explanation_ar": "تلاعب بصري في اسم النطاق (استبدال حرف l برقم 1 في paypa1)، مع إغراء بجائزة مالية وطلب كلمة المرور وOTP.",
        "explanation_en": "Typosquatting replaces 'l' with '1' in paypa1, combines an unsolicited cash prize lure, and asks for your password and OTP.",
    },
    {
        "id": "open-redirect-university",
        "channel": "Email",
        "sender": "alerts@portal-uob.info",
        "text_ar": "يرجى مراجعة تحديث المنحة الطلابية عبر الرابط التالي https://portal-uob.info/redirect?next=http://185.220.101.4/auth/login لتحديث بيانات الدخول.",
        "text_en": "Please review your student grant update via https://portal-uob.info/redirect?next=http://185.220.101.4/auth/login to verify your login credentials.",
        "is_scam": True,
        "explanation_ar": "استغلال إعادة التوجيه المفتوحة (Open Redirect): الرابط يبدأ بنطاق يبدو إدارياً لكنه يحوّلك عبر معامل next= مباشرةً إلى خادم عنوان IP خام مشبوه!",
        "explanation_en": "Open-redirect trap: the wrapper host looks administrative, but the 'next=' parameter silently forwards victims to a raw IP credential-harvesting endpoint.",
    },
    {
        "id": "team-meeting-safe",
        "channel": "WhatsApp",
        "sender": "زميل العمل",
        "text_ar": "السلام عليكم، اجتماع الفريق الساعة 11 صباحاً لمراجعة التقرير الشهري في القاعة الرئيسية. يرجى إحضار الملاحظات.",
        "text_en": "Hi team, our monthly report review meeting is at 11:00 AM in the main room. Please bring your notes.",
        "is_scam": False,
        "explanation_ar": "رسالة عمل اعتيادية خالية تماماً من الروابط المشبوهة أو الطلبات المالية أو الاستعجال التهديدي.",
        "explanation_en": "Normal workplace message with zero suspicious links, credential requests, or artificial urgency.",
    },
    {
        "id": "reverse-se-fake-charge",
        "channel": "SMS",
        "sender": "CardSecurity",
        "text_ar": "إشعار خصم مالي: تم سحب مبلغ 740$ من بطاقتك الآن. إذا لم تقم بالعملية اضغط الرابط وأرسل رمز التحقق لإلغاء السحب فوراً عبر http://cancel-tx-iq.top/refund",
        "text_en": "Debit Alert: $740 was just charged to your card. If you did not authorize this, click immediately and submit your OTP to cancel at http://cancel-tx-iq.top/refund",
        "is_scam": True,
        "explanation_ar": "خدعة السحب الوهمي (Reverse Panic Lure): يختلق خصماً مالياً كبيراً لإرباكك وجعلك تدخل رمز OTP وبيانات بطاقتك بحجة إيقاف العملية على موقع مزيف (.top).",
        "explanation_en": "Reverse panic scam: fabricates a large unauthorized charge so victims rush to hand over OTPs and card data on a fake '.top' refund page.",
    },
    {
        "id": "legit-gov-iq-portal",
        "channel": "SMS",
        "sender": "UrPortal",
        "text_ar": "بوابة أور الإلكترونية: تم إصدار وثيقتك الرقمية بنجاح. يمكنك متابعة حالة الطلب عبر المنصة الحكومية الرسمية https://ur.gov.iq في أي وقت.",
        "text_en": "Ur E-Government Portal: Your digital document has been issued. You may review your application status at https://ur.gov.iq anytime.",
        "is_scam": False,
        "explanation_ar": "إشعار حكومي رسمي سليم: النطاق ينتهي بالامتداد الحكومي العراقي الموثق (.gov.iq) ولا يتضمن طلب دفع رسوم أو رمز سري أو بيانات بطاقة.",
        "explanation_en": "Authentic government notice: links strictly to the official Iraqi '.gov.iq' portal without asking for OTPs, passwords, or payment details.",
    },
    {
        "id": "oauth-grant-trap",
        "channel": "Email",
        "sender": "grants@scholarship-assist.work",
        "text_ar": "فرصة منحة دراسية: أتمم التقديم عبر منح تطبيق المساعد صلاحية قراءة وإرسال بريدك في Gmail من خلال https://scholarship-assist.work/oauth",
        "text_en": "Scholarship opportunity: complete verification by granting our assistant app permission to read and send your Gmail via https://scholarship-assist.work/oauth",
        "is_scam": True,
        "explanation_ar": "تصيّد تفويضات OAuth (Consent Phishing): لا يسرق كلمة مرورك مباشرة بل يطلب تفويضاً خطيراً لقراءة رسائلك وإرسالها نيابة عنك من نطاق .work غير رسمي!",
        "explanation_en": "OAuth consent phishing: instead of stealing your password, it tricks you into granting an untrusted '.work' app full permission to read and send your emails.",
    },
    {
        "id": "predatory-journal-fee",
        "channel": "Email",
        "sender": "editor@fast-scopus-pay.xyz",
        "text_ar": "مجلة البحوث السريعة: تم قبول بحثك تلقائياً خلال 6 ساعات! يرجى تحويل مبلغ 180$ رسوم نشر عاجلة عبر الرابط https://fast-scopus-pay.xyz/invoice خلال 24 ساعة.",
        "text_en": "Fast Research Journal: Your manuscript was accepted in 6 hours! Please wire transfer $180 urgent publication fee at https://fast-scopus-pay.xyz/invoice within 24 hours.",
        "is_scam": True,
        "explanation_ar": "احتيال المجلات المفترسة (Predatory Journal Scam): القبول التلقائي خلال ساعات دون تحكيم حقيقي وطلب تحويل مالي عاجل عبر نطاق .xyz مؤشر واضح على النصب الأكاديمي.",
        "explanation_en": "Predatory journal scam: instant acceptance without real peer review paired with urgent fee transfer demands on a '.xyz' domain.",
    },
    {
        "id": "legit-bank-call-back-card",
        "channel": "SMS",
        "sender": "BaghdadBank",
        "text_ar": "مصرف بغداد: تم تعليق بطاقتك مؤقتاً كإجراء احترازي لحمايتك. يرجى مراجعة أقرب فرع أو الاتصال بالرقم الرسمي المطبوع خلف بطاقتك.",
        "text_en": "Bank of Baghdad: Your card was temporarily paused as a security precaution. Please visit the nearest branch or call the official number printed on the back of your card.",
        "is_scam": False,
        "explanation_ar": "تحذير مصرفي آمن تماماً: يوجهك للاتصال بالرقم المطبوع على بطاقتك أو زيارة الفرع ولا يضع أي رابط خارجي أو رقم هاتف بديل أو طلب OTP.",
        "explanation_en": "Safe security advisory: directs you to the official number printed on your physical card or branch visit—no links, no alternate numbers, and no OTP requests.",
    },
    {
        "id": "github-env-secret-lure",
        "channel": "Email",
        "sender": "security@github-actions-check.live",
        "text_ar": "تنبيه أمني للمطورين: تم رصد فشل في فحص مستودعك. يرجى تأكيد ملف .env ومفتاح API الخاص بك فوراً عبر https://github-actions-check.live/token",
        "text_en": "Developer Security Alert: Repository check failed. Please upload your .env file and API key immediately at https://github-actions-check.live/token",
        "is_scam": True,
        "explanation_ar": "تصيد يستهدف المطورين: انتحال منصة GitHub على نطاق .live مزيف لسرقة ملفات البيئة (.env) ومفاتيح API السرية للمشروع.",
        "explanation_en": "Developer-targeted phishing: impersonates GitHub on an unofficial '.live' domain to exfiltrate '.env' files and secret API tokens.",
    },
    {
        "id": "whatsapp-hijack-friend",
        "channel": "WhatsApp",
        "sender": "صديق قديم",
        "text_ar": "هلو صديقي، بالغلط دزيت رمز الـ 6 أرقام مال واتساب لرقمك، تكدر دزلي الرمز هسه ضروري لأن حسابي انقفل؟",
        "text_en": "Hey friend, I accidentally sent my 6-digit WhatsApp verification code to your phone number—can you send me the code right now?",
        "is_scam": True,
        "explanation_ar": "حيلة الاستيلاء على واتساب: حتى بدون أي رابط، الرمز الذي وصل لهاتفك هو مفتاح فتح حسابك أنت، والمحتال يستغل حساب صديق مخترق لطلبه منك.",
        "explanation_en": "WhatsApp hijacking scam: even with zero links, the 6-digit code sent to your phone unlocks YOUR account—the scammer is using a compromised friend's chat.",
    },
    {
        "id": "guaranteed-crypto",
        "channel": "Telegram",
        "sender": "VIP Trading Bot",
        "text_ar": "فرصة استثمارية حصرية: ربح يومي مضمون 400$! حول مبلغ 100$ الآن أو أرسل بطاقة هدايا عبر https://quick-profit.click لتفعيل الحساب.",
        "text_en": "Exclusive investment: guaranteed daily profit of $400! Send $100 via wire transfer or gift card at https://quick-profit.click to activate.",
        "is_scam": True,
        "explanation_ar": "احتيال استثماري واضح: الوعود بأرباح يومية مضمونة وطلب تحويل أموال أو بطاقات هدايا عبر نطاق .click غير موثوق.",
        "explanation_en": "Investment fraud: promises guaranteed daily profits and demands wire transfers or gift cards on a high-risk .click domain.",
    },
    {
        "id": "legit-conference-schedule",
        "channel": "Email",
        "sender": "committee@uotechnology.edu.iq",
        "text_ar": "اللجنة العلمية: تم نشر جدول مناقشات مشاريع التخرج ليوم الخميس في القاعة 3. الدخول مجاني للطلبة والضيوف ولا يتطلب أي تسجيل دخول.",
        "text_en": "Scientific Committee: The graduation project defense schedule for Thursday in Hall 3 is published. Free admission for students and guests with no sign-in required.",
        "is_scam": False,
        "explanation_ar": "إعلان أكاديمي موثوق: خبر عام لا يتضمن روابط تصيد أو طلب معلومات شخصية أو ضغطاً مالياً، وعبارة «الدخول مجاني» في سياق جامعي طبيعية تماماً.",
        "explanation_en": "Legitimate campus announcement: general event notice with no phishing links, credential prompts, or financial demands—'free admission' in context is benign.",
    },
]


def get_quiz_scenarios() -> list[dict[str, Any]]:
    """Return scenarios without exposing answers to the client."""
    return [
        {
            "id": item["id"],
            "channel": item["channel"],
            "sender": item["sender"],
            "text_ar": item["text_ar"],
            "text_en": item["text_en"],
        }
        for item in SCENARIOS
    ]


def verify_quiz_answer(scenario_id: str, user_says_scam: bool, lang: str = "ar") -> dict[str, Any]:
    """Grade user answer and attach Python analyzer forensic proof."""
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if scenario is None:
        raise ValueError("Unknown scenario id")

    sample_text = scenario["text_en"] if lang == "en" else scenario["text_ar"]
    analysis = analyze_message(sample_text)
    is_scam = scenario["is_scam"]
    correct = bool(user_says_scam) == is_scam

    return {
        "id": scenario["id"],
        "correct": correct,
        "is_scam": is_scam,
        "explanation_ar": scenario["explanation_ar"],
        "explanation_en": scenario["explanation_en"],
        "analysis": analysis,
    }

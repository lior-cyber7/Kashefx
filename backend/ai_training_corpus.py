"""Strictly separated TRAINING corpus for Arabic & English AI-vs-Human stylometric model fitting.

None of the samples in this module appear in `eval_datasets.py` (held-out test split).
Includes both formal/structured human texts and short-sentence AI texts to prevent
the superficial 'structured text == AI' bias.
"""

from __future__ import annotations

TRAIN_AR: list[tuple[str, int]] = [
    # --- Human Arabic (label = 0): varied styles including formal structured academic & colloquial ---
    (
        "في تجربتنا الميدانية داخل مختبر الشبكات ببغداد واجهنا مشكلة غريبة: جهاز التوجيه كان يفصل كل "
        "اربعين دقيقة بالضبط دون أي خطأ في السجلات! بعد تتبع الكابلات اكتشفنا أن مكيف الغرفة يسبب تداخلاً "
        "كهربائياً عند تشغيل الضاغط. غيّرنا مسار السلك وانتهت المشكلة فوراً، وهذا درس عملي لم نجد ذكره في الكتب.",
        0,
    ),
    (
        "تُعدّ دراسة بنية اللغة العربية في المصادر التراثية مدخلاً منهجياً لفهم تطور الدلالة عبر العصور؛ "
        "إذ لاحظ الباحثون أن الانتقال من التدوين الشفهي إلى التأليف المنظم أحدث تحولاً دقيقاً في توظيف الجمل "
        "الاعتراضية. ورغم صرامة القواعد النحوية عند سيبويه، بقيت اللهجات المحلية محتفظة بمرونة لافتة في التركيب.",
        0,
    ),
    (
        "أعتقد بصراحة أن الاعتماد الكلي على الأدوات الجاهزة أضعف مهارة القراءة النقدية لدى بعض الزملاء. "
        "بالأمس راجعت مشروع تخرج، وجدت فيه مقدمة منمّقة جداً لكن الطالب عجز عن شرح سطر واحد من خوارزميته! "
        "لماذا لا نعود لاختبارات المناقشة الشفهية البسيطة؟ هي الأصدق دائماً في قياس الفهم الحقيقي.",
        0,
    ),
    (
        "تعتمد المنهجية العلمية الرصينة في هندسة البرمجيات على توثيق المتطلبات قبل الشروع في كتابة الشيفرة "
        "المصدرية، وذلك للحد من الأخطاء المعمارية المكلفة لاحقاً. وقد أوضحت نتائج المسح الميداني لثلاث شركات "
        "عراقية عاملة في الدفع الإلكتروني أن غياب اختبارات التكامل المبكرة رفع كلفة الصيانة بنسبة ملموسة.",
        0,
    ),
    (
        "سافرتُ الأسبوع الماضي إلى البصرة لحضور ورشة عن أمن المعلومات. الجو كان حاراً نوعاً ما، لكن النقاش مع "
        "المهندسين هناك عوّض التعب كله. تكلمنا عن ثغرات تطبيقات الهواتف وكيف يقع المستخدم البسيط في فخ الروابط "
        "المختصرة على واتساب. اتفقنا في النهاية على بناء دليل توعوي بلغة مبسطة يفهمها الجميع.",
        0,
    ),
    (
        "لا يمكن اختزال أزمة السكن في عامل التمويل وحده؛ فالتخطيط الحضري العشوائي، وارتفاع كلف المواد الأولية، "
        "وتباطؤ التراخيص البلدية تشكّل معاً منظومة معقدة. لذا اقترحنا في الورقة البحثية تقسيم المشاريع إلى "
        "مراحل صغيرة قابلة للتمويل التعاوني بدل انتظار الاستثمارات العملاقة المتعثرة.",
        0,
    ),
    (
        "عندما بدأنا بناء قاعدة البيانات ظننا أن الاستعلامات ستبقى سريعة دائماً. لكن بعد وصول السجلات إلى مئتي "
        "ألف صف انهار الأداء فجأة! اضطررنا لإعادة كتابة الفهارس ليلاً قبل موعد التسليم بساعات، وتعلمنا يومها ألا "
        "نثق بالاختبارات التي تجرى على عشرات الصفوف التجريبية فقط.",
        0,
    ),
    (
        "تتفاوت قدرات الطلبة في استيعاب المفاهيم الرياضية المجردة، ولا سيما في السنة الدراسية الأولى؛ فبينما يفضل "
        "قسم منهم التمثيل البياني المباشر، يميل آخرون إلى البرهان الرمزي المجرد. ومن هنا تظهر أهمية تنويع أمثلة "
        "المحاضرة بدلاً من الاكتفاء بقراءة الشرائح الجاهزة بصوت رتيب.",
        0,
    ),
    # --- AI-generated Arabic (label = 1): varied styles including formal, concise, and balanced prose ---
    (
        "مما لا شك فيه أن التحول الرقمي يلعب دوراً حيوياً في تطوير المؤسسات التعليمية في عصرنا الحالي. "
        "علاوة على ذلك، تسهم التقنيات الحديثة في تحسين جودة الخدمات الأكاديمية وتعزيز كفاءة العمليات الإدارية. "
        "من ناحية أخرى، تجدر الإشارة إلى أهمية تأهيل الكوادر البشرية لمواكبة هذه التطورات المتسارعة. "
        "في الختام، يُعد الاستثمار في البنية التحتية الرقمية ركيزة أساسية لتحقيق التنمية المستدامة.",
        1,
    ),
    (
        "تُعد الطاقة المتجددة من أهم الحلول الاستراتيجية لمواجهة التحديات البيئية العالمية الراهنة. "
        "وبالإضافة إلى ذلك، توفر مصادر الطاقة النظيفة فرصاً اقتصادية واعدة تسهم في تقليل الاعتماد على الوقود الأحفوري. "
        "ومع ذلك، تتطلب هذه التحولات تخطيطاً محكماً واستثمارات طويلة الأمد لضمان استقرار الشبكات الكهربائية. "
        "بناءً على ما سبق، يمكن القول إن التعاون الدولي يشكل عاملاً حاسماً في تسريع الانتقال نحو مستقبل مستدام.",
        1,
    ),
    (
        "تسهم أنظمة الذكاء الاصطناعي في تحليل كميات ضخمة من البيانات بسرعة ودقة تفوق القدرات البشرية التقليدية. "
        "علاوة على ذلك، تساعد هذه الأنظمة المؤسسات على اكتشاف الأنماط الخفية واتخاذ قرارات مبنية على مؤشرات واضحة. "
        "غير أنه لا يمكن إغفال التحديات الأخلاقية والتقنية المرتبطة بخصوصية البيانات وأمن المعلومات. "
        "في نهاية المطاف، يتطلب الاستخدام المسؤول لهذه التكنولوجيا وضع أطر تنظيمية متوازنة وفعالة.",
        1,
    ),
    (
        "يمثل الأمن السيبراني خط الدفاع الأول لحماية الأصول الرقمية والبيانات الحساسة في البيئة المعاصرة. "
        "كما يعزز تطبيق سياسات الحماية الاستباقية من قدرة المؤسسات على التصدي للهجمات الإلكترونية المتطورة. "
        "وفي هذا السياق، تبرز أهمية نشر الوعي الأمني بين المستخدمين باعتبارهم الحلقة الأهم في منظومة الحماية. "
        "وختاماً، يبقى التكامل بين الحلول التقنية والتثقيف المستمر الضمان الحقيقي لبيئة رقمية آمنة.",
        1,
    ),
    (
        "تشهد تقنيات التعلم الآلي تطوراً متسارعاً ينعكس بشكل مباشر على مختلف القطاعات الحيوية كالصحة والتعليم والمالية. "
        "كما تتيح الخوارزميات الحديثة أتمتة المهام المتكررة وتقليل نسبة الأخطاء التشغيلية بصورة ملحوظة. "
        "ومن جهة أخرى، تفرض هذه الابتكارات الحاجة إلى تحديث المناهج الجامعية لتزويد الخريجين بالمهارات المطلوبة. "
        "وبذلك تتضح أهمية الشراكة الفاعلة بين الجامعات والقطاع الصناعي لتعزيز الابتكار الوطني.",
        1,
    ),
    (
        "تواجه سلاسل الإمداد الحديثة ضغوطاً متزايدة تتطلب حلولاً مرنة قادرة على التكيف مع المتغيرات الاقتصادية. "
        "تساعد أدوات التتبع الذكية على مراقبة تدفق البضائع وتحسين دقة التنبؤ بالطلب في الأسواق الإقليمية. "
        "كما تساهم الأتمتة اللوجستية في خفض التكاليف التشغيلية وتقليل زمن التسليم للعملاء بصورة منتظمة. "
        "وعليه، فإن تبني الرقمنة الشاملة يمثل خطوة محورية لرفع القدرة التنافسية للمؤسسات التجارية.",
        1,
    ),
    (
        "تعتمد جودة البحث العلمي على دقة المنهجية المستخدمة وسلامة تحليل البيانات المتاحة للباحثين. "
        "تسهم الأدوات التحليلية المتقدمة في فحص المراجع والتحقق من أصالة الأفكار المطروحة في الدراسات الأكاديمية. "
        "علاوة على ذلك، تدعم هذه الوسائل الباحثين في تنظيم المعطيات وتقديم نتائج موضوعية قابلة للقياس. "
        "ومن ثم، تظل الأمانة العلمية المعيار الأساسي الذي يضمن مصداقية الإنتاج المعرفي في الجامعات.",
        1,
    ),
    (
        "يشكّل التخطيط الاستراتيجي ركيزة جوهرية لنجاح أي مشروع تقني يسعى إلى تحقيق أثر طويل الأمد. "
        "فمن خلال تحديد الأهداف القابلة للقياس وتوزيع الموارد بكفاءة، تستطيع الفرق تجاوز العقبات التشغيلية. "
        "علاوة على ذلك، يتيح التقييم الدوري لمؤشرات الأداء تصحيح المسار في الوقت المناسب قبل تفاقم المشكلات. "
        "بشكل عام يمكن القول إن المرونة التنظيمية هي المفتاح الحقيقي لاستمرارية الأعمال ونموها.",
        1,
    ),
]

TRAIN_EN: list[tuple[str, int]] = [
    # --- Human English (label = 0): mix of structured academic prose and conversational logs ---
    (
        "Our deployment looked solid on staging until Tuesday morning, when three students uploaded "
        "scanned PDFs with weird Arabic filenames and broke the parser! Why didn't our unit tests catch "
        "that? Simple: we only tested clean ASCII strings. I spent two hours patching UTF-8 normalization "
        "before the department demo, and honestly that bug taught us more than the textbook ever did.",
        0,
    ),
    (
        "Empirical evaluation of network intrusion datasets remains constrained by class imbalance and "
        "temporal drift. Although benchmark corpora such as CIC-IDS2017 offer labeled packet flows, "
        "enterprise telemetry rarely preserves identical feature distributions across fiscal quarters. "
        "Consequently, rigorous validation requires out-of-time splits rather than random row shuffling.",
        0,
    ),
    (
        "I keep coming back to a stubborn question about automated grading: what happens when a student "
        "writes unusually concise, formal English because they learned from grammar handbooks? Falsely "
        "accusing an honest learner hurts far more than missing a slick AI paraphrase. That's why we "
        "stopped reporting raw scores without confidence intervals or inconclusive bands.",
        0,
    ),
    (
        "Thermal runaway in lithium-ion cells typically initiates when separator degradation allows an "
        "internal short circuit between anode and cathode layers. Laboratory calorimetry performed by "
        "Chen and colleagues demonstrated that electrolyte decomposition accelerates sharply above 130 C. "
        "Preventive battery management systems therefore monitor cell impedance alongside terminal voltage.",
        0,
    ),
    (
        "Last weekend we tried migrating the legacy SQLite ledger over to a fresh schema—bad idea at 11pm! "
        "Half the foreign keys failed because someone had stored dates as plain strings back in 2022. "
        "We rolled back, wrote a quick Python sanitizer script, and verified row hashes one by one. "
        "Messy? Definitely. Worth it? Yes, zero corrupt records left.",
        0,
    ),
    (
        "Public transit scheduling in mid-sized cities seldom fails for lack of optimization algorithms; "
        "instead, unexpected roadwork, driver shift handoffs, and rainstorms knock timetables off balance. "
        "Operators I interviewed preferred simple recovery buffers at transfer hubs over fragile theoretical "
        "schedules that look optimal on paper yet collapse by noon.",
        0,
    ),
    (
        "When auditing phishing kits targeting university portals, we rarely see exotic zero-day exploits. "
        "Attackers mostly clone the CSS login sheet, swap the form action to a cheap .xyz collector, "
        "and wire a Telegram bot token straight into inline JavaScript. Checking the HTML action target "
        "statically catches nearly all of them without opening a browser.",
        0,
    ),
    (
        "Why do people still fall for delivery-fee texts? Timing. If you actually ordered something two days "
        "ago, a vague SMS about customs clearance lands right inside your mental expectation window! "
        "Teaching users to check domain names helps, though stopping shorteners at the gateway works faster.",
        0,
    ),
    # --- AI-generated English (label = 1): varied styles ---
    (
        "Moreover, cybersecurity plays a crucial role in safeguarding modern digital infrastructure across "
        "educational institutions. Furthermore, it is worth noting that proactive threat detection enables "
        "organizations to mitigate evolving cyber risks effectively. On the other hand, relying solely on "
        "traditional defenses is no longer sufficient in today's rapidly evolving landscape. In conclusion, "
        "comprehensive security frameworks remain essential for long-term resilience.",
        1,
    ),
    (
        "Artificial intelligence has emerged as a transformative force across healthcare, finance, and "
        "education in the modern era. By leveraging advanced machine learning algorithms, organizations can "
        "streamline complex workflows and enhance decision-making accuracy. Furthermore, continuous innovation "
        "in data processing fosters unprecedented opportunities for operational efficiency. Ultimately, "
        "responsible governance is vital to ensure equitable and sustainable technological progress.",
        1,
    ),
    (
        "Effective project management requires clear communication, structured planning, and continuous "
        "alignment among diverse stakeholders. Moreover, establishing measurable milestones allows teams to "
        "monitor progress and address potential bottlenecks before they escalate. In addition, fostering a "
        "collaborative culture empowers individuals to contribute meaningfully to shared objectives. Thus, "
        "disciplined execution serves as the cornerstone of sustainable organizational success.",
        1,
    ),
    (
        "Climate change presents multifaceted challenges that demand coordinated global action and innovative "
        "policy solutions. Transitioning toward renewable energy sources offers a viable pathway to reducing "
        "carbon emissions while supporting economic stability. However, achieving meaningful progress requires "
        "sustained investment in infrastructure and international cooperation. In summary, collective commitment "
        "is indispensable for securing an environmentally resilient future.",
        1,
    ),
    (
        "Data privacy has become a paramount concern as digital platforms increasingly collect and analyze "
        "personal information at scale. Organizations must implement robust encryption standards and transparent "
        "consent mechanisms to maintain user trust. Furthermore, compliance with evolving regulatory frameworks "
        "ensures accountability and minimizes exposure to costly breaches. Consequently, privacy-by-design "
        "principles are integral to modern software architecture.",
        1,
    ),
    (
        "Higher education institutions face growing pressure to integrate digital literacy and critical "
        "thinking into contemporary curricula. Online learning environments provide flexible access to diverse "
        "resources, thereby broadening educational participation worldwide. Nevertheless, educators must carefully "
        "balance technological convenience with meaningful interpersonal engagement. Overall, thoughtful pedagogical "
        "design enhances student outcomes in an increasingly interconnected world.",
        1,
    ),
    (
        "Modern supply chain ecosystems rely heavily on predictive analytics to anticipate demand fluctuations "
        "and optimize inventory levels. Through real-time visibility and automated coordination, enterprises can "
        "reduce waste and strengthen responsiveness to market disruptions. Moreover, strategic partnerships "
        "across logistics networks cultivate greater agility and operational reliability. Taken together, these "
        "capabilities drive competitive advantage in global commerce.",
        1,
    ),
    (
        "Academic integrity serves as a foundational pillar of credible scholarly inquiry and intellectual growth. "
        "When researchers uphold rigorous standards of citation and transparency, the broader scientific community "
        "benefits from verifiable knowledge. Furthermore, fostering ethical awareness among students reinforces "
        "trust in educational credentials. Ultimately, preserving originality requires both institutional vigilance "
        "and supportive mentorship.",
        1,
    ),
]

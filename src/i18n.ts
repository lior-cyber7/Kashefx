import type {
  AcademicVerdict,
  BehaviorStatus,
  Language,
  ScamCategory,
  ThreatSourceStatus,
  UrlClassification,
  UrlSandboxResult,
  Verdict,
} from './types';
import { apiJson } from './utils/api';

export interface LearnItem {
  id: string;
  question: string;
  answer: string;
}

type StrMap<K extends string> = Record<K, string>;

export interface TranslationBundle {
  brandAr: string;
  brandEn: string;
  nav: StrMap<'analyzer' | 'trending' | 'quiz' | 'learn' | 'langToggle' | 'langToggleAria' | 'menuOpenAria' | 'menuCloseAria'>;
  hero: StrMap<
    | 'blurredLine1' | 'blurredLine2' | 'typewriterText' | 'analyzePill' | 'reachUsPrefix' | 'reachUsEmail' | 'copiedLabel'
    | 'headline' | 'subtitle' | 'messageLabel' | 'placeholder' | 'urlLabel' | 'urlPlaceholder' | 'detectedUrlsLabel'
    | 'analyzeButton' | 'analyzingButton' | 'clearButton' | 'privacyNote' | 'emptyError' | 'truncatedWarning'
    | 'networkError' | 'rateLimitError' | 'retryButton'
  > & {
    tabs: StrMap<'single' | 'batch' | 'urlInspector' | 'sandbox' | 'academic' | 'dlp' | 'history'>;
    examples: Array<{ id: string; label: string; text: string }>;
  };
  result: StrMap<
    | 'riskScoreLabel' | 'outOfHundred' | 'categoryLabel' | 'whyTitle' | 'noReasonsText' | 'highlightedCopyTitle'
    | 'pointsSuffix' | 'whatToDoTitle' | 'shareButton' | 'sharingButton' | 'copyWarningButton' | 'copiedWarningButton'
    | 'exportJsonButton' | 'reportButton' | 'reportingButton' | 'reportedButton' | 'reportError' | 'shareFooter'
    | 'forensicsTitle' | 'defangedLabel' | 'copyDefanged' | 'copiedDefanged' | 'sanitizedLabel' | 'entropyLabel'
    | 'officialDomainLabel' | 'impersonationLabel' | 'liveProbeButton' | 'liveProbingButton' | 'dnsLabel' | 'tlsLabel'
    | 'redirectsLabel' | 'finalUrlLabel' | 'openSandboxButton' | 'noKnownThreatNote' | 'threatIntelTitle'
    | 'rdapLabel' | 'dnsRecordsLabel' | 'technicalDetailsTitle' | 'suspiciousSegmentsTitle' | 'linksVerifyTitle' | 'scriptsLabel'
  > & {
    verdicts: StrMap<Verdict>;
    verdictSummaries: StrMap<Verdict>;
    steps: Record<Verdict, [string, string, string]>;
    urlClassifications: StrMap<UrlClassification>;
    threatStatusLabels: StrMap<ThreatSourceStatus>;
  };
  batch: StrMap<
    | 'title' | 'subtitle' | 'placeholder' | 'uploadTxtButton' | 'sampleButton' | 'scanButton'
    | 'scanningButton' | 'emptyError' | 'totalLabel' | 'dangerousLabel' | 'suspiciousLabel' | 'safeLabel' | 'inspectSingleButton'
  >;
  urlLab: StrMap<'title' | 'subtitle' | 'inputLabel' | 'placeholder' | 'inspectButton' | 'inspectingButton' | 'emptyError'>;
  urlSandbox: StrMap<
    | 'title' | 'subtitle' | 'isolationNotice' | 'inputLabel' | 'placeholder' | 'runButton' | 'runningButton'
    | 'emptyError' | 'presetPhishLabel' | 'presetApkLabel' | 'presetSafeLabel' | 'whatTitle' | 'observedTag' | 'predictedTag'
    | 'previewTitle' | 'previewSubtitle' | 'previewEmptyText' | 'previewTrapWarning' | 'telemetryTitle'
    | 'httpStatusLabel' | 'contentTypeLabel' | 'formsLabel' | 'scriptsLabel' | 'iframesLabel' | 'cookiesLabel' | 'redirectsTitle'
  > & { modeLabels: StrMap<UrlSandboxResult['execution_mode']> };
  history: StrMap<'title' | 'subtitle' | 'clearAll' | 'emptyTitle' | 'emptyBody' | 'reopenButton'>;
  quiz: StrMap<
    | 'title' | 'subtitle' | 'scoreLabel' | 'progressLabel' | 'scamButton' | 'safeButton' | 'correctBadge' | 'wrongBadge'
    | 'nextButton' | 'restartButton' | 'completedTitle' | 'completedBody' | 'pythonProofLabel' | 'badgesTitle' | 'streakLabel'
  > & { badges: Array<{ id: 'first_catch' | 'streak_three' | 'cyber_defender' | 'perfect_shield'; title: string; requirement: string }> };
  academic: StrMap<
    | 'title' | 'subtitle' | 'textLabel' | 'textPlaceholder' | 'refLabel' | 'refPlaceholder' | 'analyzeButton'
    | 'analyzingButton' | 'emptyError' | 'sampleHumanLabel' | 'sampleAiLabel' | 'samplePlagiarismLabel'
    | 'telemetryLabel' | 'telemetryAdvisory' | 'keystrokesLabel' | 'pastedLabel' | 'cadenceLabel'
    | 'originalityLabel' | 'aiProbLabel' | 'plagiarismLabel' | 'richnessLabel' | 'burstinessLabel' | 'behaviorLabel'
    | 'signalsTitle' | 'plagiarismMatchesTitle' | 'certEligibleTitle' | 'certEligibleSubtitle'
    | 'certTitleLabel' | 'certTitlePlaceholder' | 'certAuthorLabel' | 'certAuthorPlaceholder'
    | 'certInstitutionLabel' | 'certInstitutionPlaceholder' | 'issueCertButton' | 'issuingCertButton' | 'certFormError'
    | 'certIssuedTitle' | 'certIdLabel' | 'blockIndexLabel' | 'docHashLabel' | 'blockHashLabel' | 'copyCertIdButton' | 'copiedCertIdButton'
  > & {
    samples: StrMap<'human' | 'ai' | 'plagiarism'>;
    verdicts: StrMap<AcademicVerdict>;
    behaviorStatuses: StrMap<BehaviorStatus>;
  };
  dlp: StrMap<
    | 'title' | 'subtitle' | 'textLabel' | 'textPlaceholder' | 'uploadFileButton' | 'sampleLeakButton'
    | 'sampleLeak' | 'scanButton' | 'scanningButton' | 'emptyError' | 'riskLabel' | 'findingsTitle' | 'noSecretsText' | 'urlsTitle'
  >;
  categories: StrMap<ScamCategory>;
  trending: StrMap<
    | 'title' | 'subtitle' | 'last7Days' | 'reportsUnit' | 'avgScoreLabel' | 'totalReportsStat'
    | 'avgRiskStat' | 'topCategoryStat' | 'emptyTitle' | 'emptyBody' | 'errorText' | 'retryButton'
  >;
  learn: { title: string; subtitle: string; items: LearnItem[] };
  footer: StrMap<'disclaimer' | 'privacyReminder'>;
}

const EMPTY = new Proxy({} as Record<string, string>, {
  get: (target, prop) => (typeof prop === 'string' ? (target[prop] ?? '') : undefined),
});

function blank<T>(overrides?: Record<string, unknown>): T {
  return new Proxy(overrides ?? {}, {
    get: (target, prop) => (typeof prop === 'string' && prop in target ? target[prop] : ''),
  }) as unknown as T;
}

function makeBootBundle(lang: Language): TranslationBundle {
  const ar = lang === 'ar';
  return {
    brandAr: 'كشف',
    brandEn: 'Kashf',
    nav: ar
      ? { analyzer: 'الفاحص', trending: 'الاحتيالات', quiz: 'اختبر وعيك', learn: 'تعلّم', langToggle: 'English', langToggleAria: 'Switch language to English', menuOpenAria: 'فتح القائمة', menuCloseAria: 'إغلاق القائمة' }
      : { analyzer: 'Analyzer', trending: 'Trending', quiz: 'IQ Lab', learn: 'Learn', langToggle: 'العربية', langToggleAria: 'التبديل إلى اللغة العربية', menuOpenAria: 'Open menu', menuCloseAria: 'Close menu' },
    hero: {
      blurredLine1: ar ? 'أهلاً بك في كشف،' : 'Hey there, meet Kashf,',
      blurredLine2: ar ? 'محلّل الرسائل والروابط المشبوهة محلياً بالبايثون' : 'Your Python-Powered Scam & URL Forensics Suite',
      typewriterText: ar ? 'هل وصلتك رسالة مشبوهة؟ الصقها هنا ونكشفها لك فوراً.' : 'Got a suspicious message? Paste it below and we will expose it.',
      analyzePill: ar ? 'ابدأ الفحص الآن' : 'Analyze a message',
      reachUsPrefix: ar ? 'تواصل معنا:' : 'Reach us:',
      reachUsEmail: 'hydrnjah52@gmail.com',
      copiedLabel: ar ? 'تم النسخ' : 'Copied',
      headline: ar ? 'منصة الفحص الأمني بالبايثون' : 'Python Security & Scam Inspector',
      subtitle: ar ? 'تحليل فوري للرسائل النصية، فحص دفعات الواتساب، وتشريح الروابط تقنياً (DNS / SSL) دون حفظ نص رسالتك.' : 'Instant SMS/WhatsApp triage, multi-message batch scanning, and live DNS/TLS link forensics without storing your text.',
      tabs: ar
        ? { single: 'فحص رسالة', batch: 'فحص متعدد', urlInspector: 'تشريح رابط', sandbox: 'Sandbox الآمن', academic: 'حصانة الأكاديمية', dlp: 'فحص التسريب والملفات', history: 'السجل المحلي' }
        : { single: 'Single Message', batch: 'Batch Scan', urlInspector: 'URL X-Ray', sandbox: 'Safe Sandbox', academic: 'Academic Shield', dlp: 'DLP & Files', history: 'Local History' },
      messageLabel: ar ? 'نص الرسالة المشبوهة' : 'Suspicious message text',
      placeholder: '',
      urlLabel: ar ? 'رابط مشبوه (اختياري — يُملأ تلقائياً عند اكتشاف رابط)' : 'Suspicious URL (optional — auto-filled if detected)',
      urlPlaceholder: 'https://example.com',
      detectedUrlsLabel: ar ? 'الروابط المكتشفة:' : 'Detected links:',
      analyzeButton: ar ? 'افحص الآن' : 'Analyze Now',
      analyzingButton: ar ? 'جارِ الفحص...' : 'Analyzing...',
      clearButton: ar ? 'مسح' : 'Clear',
      privacyNote: ar ? 'لا نحفظ نص رسالتك. نحفظ فقط بصمة مجهولة للإحصائيات.' : 'We never store your message text. Only an anonymous fingerprint is kept for statistics.',
      emptyError: ar ? 'يرجى لصق نص الرسالة أو إدخال رابط لفحصه أولاً.' : 'Please paste a message or enter a link to analyze first.',
      truncatedWarning: '',
      networkError: ar ? 'تعذر الاتصال بخادم الفحص. تأكد من تشغيل الخادم ثم أعد المحاولة.' : 'Could not reach the analysis server. Please check the backend and try again.',
      rateLimitError: ar ? 'تم إرسال طلبات كثيرة خلال دقيقة واحدة. انتظر قليلاً ثم أعد المحاولة.' : 'Too many requests in one minute. Please wait briefly and try again.',
      retryButton: ar ? 'إعادة المحاولة' : 'Try Again',
      examples: [
        { id: 'bank', label: ar ? 'رسالة بنك' : 'Bank Alert', text: ar ? 'تنبيه من مصرف الرافدين: سيتم إيقاف حسابك خلال 24 ساعة. يرجى تحديث رقم البطاقة ورمز التحقق فوراً عبر http://rafidain-verify.xyz/update' : 'Rafidain Bank Alert: Your account will be suspended within 24 hours. Verify your card number and OTP immediately at http://rafidain-verify.xyz/update' },
        { id: 'prize', label: ar ? 'جائزة وهمية' : 'Fake Prize', text: 'مبروك! ربحت 5000$، اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل رمز التحقق' },
        { id: 'delivery', label: ar ? 'رابط توصيل' : 'Delivery Link', text: ar ? 'البريد العراقي: تعذر التسليم لوجود طردك في المستودع. ادفع رسوم جمركية بسيطة عبر bit.ly/3x9demo لتأكيد العنوان فوراً.' : 'Delivery failed: Your package is held pending a small customs fee. Pay via bit.ly/3x9demo within 24 hours.' },
      ],
    },
    result: blank({
      outOfHundred: '/ 100',
      verdicts: EMPTY,
      verdictSummaries: EMPTY,
      steps: { safe: ['', '', ''], suspicious: ['', '', ''], dangerous: ['', '', ''] },
      urlClassifications: EMPTY,
      threatStatusLabels: EMPTY,
    }),
    batch: blank(),
    urlLab: blank(),
    urlSandbox: blank({ modeLabels: EMPTY }),
    history: blank(),
    quiz: blank({ badges: [] }),
    academic: blank({
      samples: EMPTY,
      verdicts: EMPTY,
      behaviorStatuses: EMPTY,
    }),
    dlp: blank(),
    categories: EMPTY as StrMap<ScamCategory>,
    trending: blank({ title: ar ? 'الاحتيالات الرائجة' : 'Trending Scams', retryButton: ar ? 'تحديث' : 'Refresh' }),
    learn: { title: ar ? 'تعلّم كيف تحمي نفسك' : 'Learn How to Stay Safe', subtitle: '', items: [] },
    footer: blank(),
  };
}

export const BOOT_I18N: Record<Language, TranslationBundle> = {
  ar: makeBootBundle('ar'),
  en: makeBootBundle('en'),
};

export function fetchI18nBundles(): Promise<Record<Language, TranslationBundle>> {
  return apiJson<Record<Language, TranslationBundle>>('/api/i18n');
}

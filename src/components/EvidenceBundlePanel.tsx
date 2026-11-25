import type { EvidenceBundle, EvidenceStrength, Language, RiskLevel } from '../types';

interface EvidenceBundlePanelProps {
  bundle: EvidenceBundle;
  lang: Language;
  hideEvidenceList?: boolean;
}

const RISK_LABEL: Record<Language, Record<RiskLevel, string>> = {
  ar: {
    critical: 'حرج (Critical)',
    high: 'مرتفع (High)',
    medium: 'متوسط (Medium)',
    low: 'منخفض (Low)',
    minimal: 'أدنى حد (Minimal)',
  },
  en: {
    critical: 'Critical Risk',
    high: 'High Risk',
    medium: 'Medium Risk',
    low: 'Low Risk',
    minimal: 'Minimal Risk',
  },
};

const STRENGTH_LABEL: Record<Language, Record<EvidenceStrength, string>> = {
  ar: {
    strong: 'قوية',
    moderate: 'متوسطة',
    weak: 'محدودة',
    insufficient: 'غير كافية',
  },
  en: {
    strong: 'Strong',
    moderate: 'Moderate',
    weak: 'Limited',
    insufficient: 'Insufficient',
  },
};

const RISK_TEXT_CLASS: Record<RiskLevel, string> = {
  critical: 'text-[#dc2626]',
  high: 'text-[#dc2626]',
  medium: 'text-[#d97706]',
  low: 'text-black/75',
  minimal: 'text-[#16a34a]',
};

export function EvidenceBundlePanel({
  bundle,
  lang,
  hideEvidenceList = false,
}: EvidenceBundlePanelProps) {
  const isAr = lang === 'ar';
  const { confidence, conflicts, limitations, evidence, risk_level, scan_timestamp } = bundle;

  return (
    <div
      className="space-y-4 border-t border-black/10 pt-5 text-start"
      data-testid="evidence-bundle-panel"
    >
      {/* Confidence, Evidence Strength & Timestamp Metadata Line */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-black/65">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`font-medium ${RISK_TEXT_CLASS[risk_level]}`}>
            {isAr ? 'مستوى الخطورة:' : 'Risk Level:'} {RISK_LABEL[lang][risk_level]}
          </span>
          <span aria-hidden="true">·</span>
          <span>
            {isAr ? 'قوة الأدلة:' : 'Evidence Strength:'}{' '}
            <strong className="font-medium text-black">
              {STRENGTH_LABEL[lang][confidence.evidence_strength]}
            </strong>
          </span>
          {confidence.detection_ratio ? (
            <>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums text-black" dir="ltr">
                VT {confidence.detection_ratio}
              </span>
            </>
          ) : null}
          {confidence.calibrated && confidence.calibrated_probability !== null ? (
            <>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums text-black">
                {isAr ? 'احتمالية معايرة:' : 'Calibrated Prob:'}{' '}
                {Math.round(confidence.calibrated_probability * 100)}%
              </span>
            </>
          ) : null}
        </div>
        <time
          dateTime={scan_timestamp}
          className="font-mono text-[11px] tabular-nums text-black/50"
          dir="ltr"
        >
          {scan_timestamp}
        </time>
      </div>

      {/* Confidence explanation */}
      <p className="text-xs leading-relaxed text-black/75">
        {isAr ? confidence.explanation_ar : confidence.explanation_en}
      </p>

      {/* Conflicts alert when sources disagree */}
      {conflicts.length > 0 ? (
        <div
          className="rounded-xl border border-[#d97706]/35 bg-[#d97706]/10 p-3.5 text-xs"
          data-testid="source-conflicts"
          role="status"
        >
          <p className="font-medium text-[#78350f]">
            {isAr
              ? 'تنبيه تعارض بين المصادر (Source Disagreement)'
              : 'Source Disagreement Detected'}
          </p>
          <ul className="mt-2 space-y-1.5 text-[#78350f]">
            {conflicts.map((c, idx) => (
              <li key={idx}>
                <span className="font-medium">{isAr ? c.topic_ar : c.topic_en}</span>
                {' — '}
                <span className="font-mono" dir="ltr">
                  {c.source_a}: {c.result_a} vs {c.source_b}: {c.result_b}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Structured Evidence list with Source & Timestamp */}
      {!hideEvidenceList && evidence.length > 0 ? (
        <div>
          <h4 className="text-xs font-medium text-black">
            {isAr ? 'الأدلة التقنية المرصودة ومصادرها' : 'Evidence Found & Source Attribution'}
          </h4>
          <ul className="mt-2 divide-y divide-black/10 rounded-xl border border-black/10 bg-[#f7f7f5] px-3.5">
            {evidence.map((item, idx) => (
              <li key={`${item.id}-${idx}`} className="py-2.5 text-xs">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span
                    className={`font-medium ${
                      item.severity === 'critical' || item.severity === 'high'
                        ? 'text-[#dc2626]'
                        : item.severity === 'medium'
                          ? 'text-[#d97706]'
                          : item.severity === 'safe'
                            ? 'text-[#16a34a]'
                            : 'text-black'
                    }`}
                  >
                    {isAr ? item.title_ar : item.title_en}
                  </span>
                  <span className="font-mono text-[11px] tabular-nums text-black/50" dir="ltr">
                    {item.source} · {item.timestamp}
                  </span>
                </div>
                <p className="mt-1 leading-relaxed text-black/70">
                  {isAr ? item.detail_ar : item.detail_en}
                </p>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Limitations */}
      {limitations.length > 0 ? (
        <div
          className="rounded-xl border border-black/10 bg-[#f7f7f5] p-3.5 text-xs text-black/70"
          data-testid="scan-limitations"
        >
          <p className="font-medium text-black">
            {isAr ? 'حدود الفحص والشفافية (Limitations)' : 'Analysis Scope & Limitations'}
          </p>
          <ul className="mt-1.5 space-y-1">
            {limitations.map((lim, idx) => (
              <li key={`${lim.code}-${idx}`}>· {isAr ? lim.ar : lim.en}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

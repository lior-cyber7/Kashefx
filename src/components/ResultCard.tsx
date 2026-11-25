import { useState } from 'react';
import type {
  AnalysisReason,
  AnalysisResult,
  GroupedSuspiciousSegment,
  Language,
  Verdict,
} from '../types';
import type { TranslationBundle } from '../i18n';
import { downloadShareCard } from '../utils/shareCard';
import { RiskGauge } from './RiskGauge';
import { UrlForensicsPanel } from './UrlForensicsPanel';
import { EvidenceBundlePanel } from './EvidenceBundlePanel';

interface ResultCardProps {
  result: AnalysisResult;
  analyzedText: string;
  lang: Language;
  t: TranslationBundle;
  reporting: boolean;
  reported: boolean;
  reportError: string | null;
  onReport: () => Promise<boolean>;
  onOpenSandbox?: (url: string) => void;
}

const VERDICT_TEXT_CLASS: Record<Verdict, string> = {
  safe: 'text-[#16a34a]',
  suspicious: 'text-[#d97706]',
  dangerous: 'text-[#dc2626]',
};

const VERDICT_MARK_CLASS: Record<Verdict, string> = {
  safe: 'bg-[#16a34a]/15 text-[#14532d] underline decoration-[#16a34a]/60 underline-offset-4',
  suspicious:
    'bg-[#d97706]/15 text-[#78350f] underline decoration-[#d97706]/60 underline-offset-4',
  dangerous:
    'bg-[#dc2626]/15 text-[#7f1d1d] underline decoration-[#dc2626]/70 underline-offset-4',
};

export function ResultCard({
  result,
  analyzedText,
  lang,
  t,
  reporting,
  reported,
  reportError,
  onReport,
  onOpenSandbox,
}: ResultCardProps) {
  const [sharing, setSharing] = useState(false);
  const [copiedWarning, setCopiedWarning] = useState(false);

  const verdictLabel = t.result.verdicts[result.verdict];
  const categoryLabel = t.categories[result.category] ?? t.categories.other;
  const segments: NonNullable<AnalysisResult['highlight_segments']> =
    result.highlight_segments && result.highlight_segments.length > 0
      ? result.highlight_segments
      : analyzedText
        ? [{ text: analyzedText, highlighted: false }]
        : [];
  const groupedSegments: GroupedSuspiciousSegment[] = result.grouped_suspicious_segments ?? [];
  const steps =
    result.recommended_actions && result.recommended_actions.length > 0
      ? result.recommended_actions.map((a) => (lang === 'ar' ? a.ar : a.en))
      : t.result.steps[result.verdict];

  const handleShare = async () => {
    if (sharing) return;
    setSharing(true);
    try {
      await downloadShareCard({
        score: result.score,
        verdict: result.verdict,
        category: result.category,
        lang,
      });
    } finally {
      setSharing(false);
    }
  };

  const handleCopyWarning = async () => {
    const text =
      result.family_warning?.[lang] ??
      `${verdictLabel} (${result.score}/100) — ${categoryLabel}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedWarning(true);
      setTimeout(() => setCopiedWarning(false), 1800);
    } catch {
      setCopiedWarning(false);
    }
  };

  const handleExportJson = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      engine: 'kashf-python-analyzer',
      result,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `kashf-report-${result.fingerprint}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <section
      aria-live="polite"
      data-testid="analysis-result"
      data-verdict={result.verdict}
      className="kashf-result-enter mt-8 rounded-2xl border border-black/10 bg-white p-6 text-black sm:p-8"
    >
      <div className="flex flex-col items-center gap-6 md:flex-row md:items-start md:gap-8">
        <div className="shrink-0">
          <RiskGauge
            score={result.score}
            verdict={result.verdict}
            scoreLabel={t.result.riskScoreLabel}
            outOfHundred={t.result.outOfHundred}
          />
        </div>

        <div className="flex-1 text-start">
          <div className="flex flex-wrap items-center gap-2.5 text-sm text-black/60">
            <span>
              {t.result.categoryLabel}: {categoryLabel}
            </span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">
              {result.reasons.length}{' '}
              {lang === 'ar' ? 'مؤشرات مرصودة' : 'signals detected'}
            </span>
          </div>

          <h2
            className={`mt-2 text-2xl font-medium sm:text-3xl ${VERDICT_TEXT_CLASS[result.verdict]}`}
            style={{ fontFamily: 'var(--font-heading)' }}
            data-testid="verdict-label"
          >
            {verdictLabel}
          </h2>

          <p className="mt-2.5 max-w-2xl text-base leading-relaxed text-black/75">
            {t.result.verdictSummaries[result.verdict]}
          </p>

          <div className="mt-5 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleShare}
              disabled={sharing}
              className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
            >
              {sharing ? t.result.sharingButton : t.result.shareButton}
            </button>

            <button
              type="button"
              onClick={() => void handleCopyWarning()}
              className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
            >
              {copiedWarning ? t.result.copiedWarningButton : t.result.copyWarningButton}
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
            >
              {t.result.exportJsonButton}
            </button>

            <button
              type="button"
              onClick={() => void onReport()}
              disabled={reporting || reported}
              className={`inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border px-4 py-2 text-xs font-medium transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black ${
                reported
                  ? 'border-[#16a34a]/40 bg-[#16a34a]/10 text-[#16a34a]'
                  : 'border-black/15 bg-white text-black hover:bg-black hover:text-white disabled:opacity-60'
              }`}
            >
              {reporting
                ? t.result.reportingButton
                : reported
                  ? t.result.reportedButton
                  : t.result.reportButton}
            </button>
          </div>

          {reportError ? (
            <p className="mt-2 text-xs text-[#dc2626]" role="alert">
              {reportError}
            </p>
          ) : null}
        </div>
      </div>

      {/* Highlighted read-only copy of the message */}
      {analyzedText ? (
        <div className="mt-8 border-t border-black/10 pt-6 text-start">
          <h3 className="text-sm font-medium text-black">
            {t.result.highlightedCopyTitle}
          </h3>
          <div
            data-testid="highlighted-message"
            className="mt-3 rounded-xl border border-black/10 bg-[#f7f7f5] p-4 text-sm leading-7 text-black whitespace-pre-wrap break-words"
          >
            {segments.map((seg, index) =>
              seg.highlighted ? (
                <mark
                  key={`${index}-${seg.text}`}
                  className={`rounded px-1 py-0.5 font-medium ${VERDICT_MARK_CLASS[result.verdict]}`}
                >
                  {seg.text}
                </mark>
              ) : (
                <span key={`${index}-${seg.text.slice(0, 8)}`}>{seg.text}</span>
              ),
            )}
          </div>
        </div>
      ) : null}

      {/* Extracted Suspicious Segments (pre-grouped by Python backend) */}
      {groupedSegments.length > 0 ? (
        <div
          className="mt-8 border-t border-black/10 pt-6 text-start"
          data-testid="suspicious-segments"
        >
          <h3 className="text-base font-medium text-black">
            {t.result.suspiciousSegmentsTitle}
          </h3>
          <ul className="mt-3 space-y-2.5">
            {groupedSegments.map((seg, idx) => {
              const labels = lang === 'ar' ? seg.labels_ar : seg.labels_en;
              const reasons = lang === 'ar' ? seg.reasons_ar : seg.reasons_en;
              return (
                <li
                  key={idx}
                  className="rounded-xl border border-black/10 bg-[#f7f7f5] p-3.5 text-sm"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span
                      className={`font-medium ${
                        seg.severity === 'critical' || seg.severity === 'high'
                          ? 'text-[#dc2626]'
                          : 'text-[#d97706]'
                      }`}
                    >
                      {labels.join(' · ')}
                    </span>
                    <span className="font-mono text-[11px] text-black/55">{seg.severity}</span>
                  </div>
                  <p className="mt-1.5 font-medium text-black">“{seg.text}”</p>
                  <p className="mt-1 text-xs leading-relaxed text-black/70">
                    {reasons.join(' · ')}
                  </p>
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}

      {/* Links Requiring Separate Verification */}
      {result.links_requiring_verification && result.links_requiring_verification.length > 0 ? (
        <div
          className="mt-8 border-t border-black/10 pt-6 text-start"
          data-testid="links-verification"
        >
          <h3 className="text-base font-medium text-black">{t.result.linksVerifyTitle}</h3>
          <ul className="mt-3 space-y-2">
            {result.links_requiring_verification.map((link) => (
              <li
                key={link.defanged_url}
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-black/10 bg-[#f7f7f5] px-4 py-3 text-xs"
              >
                <div className="min-w-0 flex-1">
                  <code className="block truncate font-mono font-medium text-black" dir="ltr">
                    {link.defanged_url}
                  </code>
                  <p className="mt-1 text-black/70">
                    {lang === 'ar' ? link.reason_ar : link.reason_en}
                  </p>
                </div>
                {onOpenSandbox ? (
                  <button
                    type="button"
                    onClick={() => onOpenSandbox(link.url)}
                    className="inline-flex min-h-8 shrink-0 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-3 py-1 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
                  >
                    {t.result.openSandboxButton}
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Python URL Forensics X-Ray */}
      {result.url_forensics && result.url_forensics.length > 0 ? (
        <div className="mt-8 border-t border-black/10 pt-6 text-start" data-testid="result-url-forensics">
          <h3 className="text-lg font-medium text-black">{t.result.forensicsTitle}</h3>
          <div className="mt-4 space-y-3">
            {result.url_forensics.map((forensics) => (
              <UrlForensicsPanel
                key={forensics.original_url}
                forensics={forensics}
                lang={lang}
                t={t}
                onOpenSandbox={onOpenSandbox}
              />
            ))}
          </div>
        </div>
      ) : null}

      {/* Why? list */}
      <div className="mt-8 border-t border-black/10 pt-6 text-start">
        <h3 className="text-lg font-medium text-black">{t.result.whyTitle}</h3>
        {result.reasons.length === 0 ? (
          <p className="mt-3 text-sm text-black/60">{t.result.noReasonsText}</p>
        ) : (
          <ul className="mt-4 divide-y divide-black/10" data-testid="reasons-list">
            {result.reasons.map((reason: AnalysisReason, idx: number) => (
              <li
                key={`${reason.id}-${idx}`}
                className="flex items-start gap-3.5 py-3.5 first:pt-0 last:pb-0"
              >
                <span
                  aria-hidden="true"
                  className="mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full bg-black"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="text-sm font-medium text-black">
                      {lang === 'ar' ? reason.title_ar : reason.title_en}
                    </span>
                    <span className="text-xs tabular-nums text-black/55">
                      +{reason.points} {t.result.pointsSuffix}
                    </span>
                  </div>
                  <p className="mt-1 text-sm leading-relaxed text-black/70">
                    {lang === 'ar' ? reason.detail_ar : reason.detail_en}
                  </p>
                  {reason.match ? (
                    <p className="mt-1.5 text-xs text-black/60">
                      <span>{lang === 'ar' ? 'العبارة المرصودة: ' : 'Matched: '}</span>
                      <span className="font-mono text-black underline decoration-black/30 underline-offset-2 break-all">
                        {reason.match}
                      </span>
                    </p>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* What should I do? */}
      <div className="mt-8 border-t border-black/10 pt-6 text-start">
        <h3 className="text-lg font-medium text-black">{t.result.whatToDoTitle}</h3>
        <ol className="mt-4 space-y-3">
          {steps.map((step, index) => (
            <li
              key={index}
              className="flex items-start gap-3 text-sm leading-relaxed text-black/80"
            >
              <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-black/15 text-xs font-medium tabular-nums text-black">
                {index + 1}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Evidence, Limitations & Timestamp */}
      {result.evidence_bundle ? (
        <div className="mt-8">
          <EvidenceBundlePanel bundle={result.evidence_bundle} lang={lang} hideEvidenceList />
        </div>
      ) : null}
    </section>
  );
}

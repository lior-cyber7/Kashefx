import { useRef, useState, type ChangeEvent, type ClipboardEvent, type FormEvent, type KeyboardEvent } from 'react';
import { Award, Check, Copy, FileCheck2, Fingerprint, ShieldAlert, ShieldCheck } from 'lucide-react';
import type {
  AcademicAnalysisResult,
  CertificateRecord,
  Language,
} from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';
import {
  buildBehaviorTelemetry,
  classifyBehaviorPreview,
} from '../utils/behaviorTracker';
import { EvidenceBundlePanel } from './EvidenceBundlePanel';

interface AcademicShieldProps {
  lang: Language;
  t: TranslationBundle;
  onCertificateIssued?: () => void;
}

export function AcademicShield({ lang, t, onCertificateIssued }: AcademicShieldProps) {
  const [text, setText] = useState('');
  const [referenceText, setReferenceText] = useState('');
  const [showRef, setShowRef] = useState(false);

  // Live behavioral typing metrics
  const lastKeyTimeRef = useRef<number | null>(null);
  const intervalsRef = useRef<number[]>([]);
  const [keystrokes, setKeystrokes] = useState(0);
  const [pastedChars, setPastedChars] = useState(0);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AcademicAnalysisResult | null>(null);

  // Blockchain certificate issuance state
  const [certTitle, setCertTitle] = useState('');
  const [certAuthor, setCertAuthor] = useState('');
  const [certInstitution, setCertInstitution] = useState(
    lang === 'ar'
      ? 'الجامعة التكنولوجية — قسم علوم الحاسوب'
      : 'University of Technology — Computer Science'
  );
  const [issuing, setIssuing] = useState(false);
  const [certError, setCertError] = useState<string | null>(null);
  const [issuedCert, setIssuedCert] = useState<CertificateRecord | null>(null);
  const [copiedId, setCopiedId] = useState(false);

  const telemetry = buildBehaviorTelemetry({
    intervalsMs: intervalsRef.current,
    keystrokes,
    pastedChars,
    totalChars: text.length,
  });
  const livePreview = classifyBehaviorPreview(telemetry);

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (
      e.ctrlKey ||
      e.metaKey ||
      e.altKey ||
      ['Shift', 'Control', 'Alt', 'Meta', 'Tab', 'CapsLock', 'Escape'].includes(e.key)
    ) {
      return;
    }
    const now = performance.now();
    if (lastKeyTimeRef.current !== null) {
      const delta = now - lastKeyTimeRef.current;
      if (delta >= 10 && delta <= 2500) {
        intervalsRef.current = [...intervalsRef.current.slice(-199), delta];
      }
    }
    lastKeyTimeRef.current = now;
    setKeystrokes((prev) => prev + 1);
  };

  const handlePaste = (e: ClipboardEvent<HTMLTextAreaElement>) => {
    const pasted = e.clipboardData?.getData('text') ?? '';
    if (pasted.length > 0) {
      setPastedChars((prev) => prev + pasted.length);
    }
  };

  const handleTextChange = (e: ChangeEvent<HTMLTextAreaElement>) => {
    setText(e.target.value);
    setError(null);
    if (e.target.value.length === 0) {
      intervalsRef.current = [];
      lastKeyTimeRef.current = null;
      setKeystrokes(0);
      setPastedChars(0);
    }
  };

  const loadSample = (kind: 'human' | 'ai' | 'plagiarism') => {
    const sample = t.academic.samples[kind];
    if (!sample) return;
    setText(sample);
    setError(null);
    setResult(null);
    setIssuedCert(null);
    setCertError(null);
    intervalsRef.current = [];
    lastKeyTimeRef.current = null;
    setKeystrokes(0);
    setPastedChars(kind === 'human' ? 0 : sample.length);
  };

  const handleAnalyze = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = text.trim();
    if (trimmed.length < 10) {
      setError(t.academic.emptyError);
      return;
    }

    setLoading(true);
    setError(null);
    setIssuedCert(null);
    setCertError(null);
    try {
      const data = await apiJson<AcademicAnalysisResult>('/api/academic/analyze', {
        text: trimmed,
        reference_text: referenceText.trim() || null,
        behavior:
          keystrokes > 0 || pastedChars > 0
            ? {
                keystrokes,
                pasted_chars: pastedChars,
                total_chars: trimmed.length,
                intervals_ms: intervalsRef.current,
              }
            : null,
      });
      setResult(data);
    } catch (err) {
      setError(getApiErrorMessage(err, t.hero));
    } finally {
      setLoading(false);
    }
  };

  const handleIssueCertificate = async (e: FormEvent) => {
    e.preventDefault();
    if (!result) return;
    if (certTitle.trim().length < 2 || certAuthor.trim().length < 2) {
      setCertError(t.academic.certFormError);
      return;
    }

    setIssuing(true);
    setCertError(null);
    try {
      const cert = await apiJson<CertificateRecord>('/api/certificates/issue', {
        title: certTitle.trim(),
        author: certAuthor.trim(),
        institution: certInstitution.trim(),
        text: text.trim(),
        originality_score: result.originality_score,
      });
      setIssuedCert(cert);
      onCertificateIssued?.();
    } catch (err) {
      setCertError(getApiErrorMessage(err, t.hero));
    } finally {
      setIssuing(false);
    }
  };

  const handleCopyCertId = async () => {
    if (!issuedCert) return;
    try {
      await navigator.clipboard.writeText(issuedCert.cert_id);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 1800);
    } catch {
      // Ignore clipboard failures
    }
  };

  const verdictAccent = (v: AcademicAnalysisResult['verdict']) => {
    if (v === 'authentic') return 'text-[#16a34a]';
    if (v === 'review_needed') return 'text-[#d97706]';
    return 'text-[#dc2626]';
  };

  return (
    <div className="mt-6 text-start" data-testid="academic-shield">
      <form
        onSubmit={handleAnalyze}
        noValidate
        className="rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-medium text-black">{t.academic.title}</h2>
            <p className="mt-1 max-w-3xl text-sm text-black/65">{t.academic.subtitle}</p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => loadSample('human')}
              className="min-h-8 whitespace-nowrap rounded-full border border-black/15 bg-white px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white"
            >
              {t.academic.sampleHumanLabel}
            </button>
            <button
              type="button"
              onClick={() => loadSample('ai')}
              className="min-h-8 whitespace-nowrap rounded-full border border-black/15 bg-white px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white"
            >
              {t.academic.sampleAiLabel}
            </button>
            <button
              type="button"
              onClick={() => loadSample('plagiarism')}
              className="min-h-8 whitespace-nowrap rounded-full border border-black/15 bg-white px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white"
            >
              {t.academic.samplePlagiarismLabel}
            </button>
          </div>
        </div>

        <div className="mt-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label
              htmlFor="academic-textarea"
              className="text-sm font-medium text-black"
            >
              {t.academic.textLabel}
            </label>
            <span className="text-xs tabular-nums text-black/50">
              {text.length} / 15000
            </span>
          </div>

          <textarea
            id="academic-textarea"
            value={text}
            onChange={handleTextChange}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            placeholder={t.academic.textPlaceholder}
            rows={6}
            className="mt-2 min-h-[160px] w-full resize-y rounded-2xl border border-black/15 bg-[#f7f7f5] p-4 text-sm leading-relaxed text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20"
          />

          {/* Live behavioral typing biometrics bar */}
          <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-black/10 bg-[#f7f7f5] px-3.5 py-2 text-xs text-black/70">
            <div className="flex items-center gap-2 font-medium text-black">
              <Fingerprint className="h-4 w-4 text-black/70" aria-hidden="true" />
              <span>{t.academic.telemetryLabel}</span>
              <span
                className={
                  livePreview === 'human_cadence'
                    ? 'text-[#16a34a]'
                    : livePreview === 'paste_heavy'
                      ? 'text-[#d97706]'
                      : 'text-black/60'
                }
              >
                {livePreview === 'human_cadence'
                  ? t.academic.behaviorStatuses.human_verified
                  : livePreview === 'paste_heavy'
                    ? t.academic.behaviorStatuses.bulk_pasted
                    : t.academic.behaviorStatuses.not_captured}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-3 tabular-nums text-black/60">
              <span>
                {t.academic.keystrokesLabel}: <strong className="text-black">{telemetry.keystrokes}</strong>
              </span>
              <span>
                {t.academic.pastedLabel}: <strong className="text-black">{telemetry.pasted_chars}</strong>
              </span>
              <span>
                {t.academic.cadenceLabel}: <strong className="text-black">{telemetry.interval_std_ms} ms</strong>
              </span>
            </div>
          </div>
          <p className="mt-1.5 text-[11px] text-black/55">{t.academic.telemetryAdvisory}</p>
        </div>

        <div className="mt-3">
          <button
            type="button"
            onClick={() => setShowRef((prev) => !prev)}
            className="text-xs font-medium text-black/70 underline underline-offset-2 hover:text-black"
          >
            {t.academic.refLabel}
          </button>

          {showRef ? (
            <textarea
              id="academic-reference-textarea"
              value={referenceText}
              onChange={(e) => setReferenceText(e.target.value)}
              placeholder={t.academic.refPlaceholder}
              rows={3}
              className="mt-2 w-full resize-y rounded-xl border border-black/15 bg-[#f7f7f5] p-3 text-sm leading-relaxed text-black placeholder:text-black/40 focus:border-black focus:outline-none"
            />
          ) : null}
        </div>

        {error ? (
          <p className="mt-3 text-sm font-medium text-[#dc2626]" role="alert">
            {error}
          </p>
        ) : null}

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={loading}
            className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
          >
            {loading ? t.academic.analyzingButton : t.academic.analyzeButton}
          </button>
        </div>
      </form>

      {result ? (
        <div
          className="kashf-result-enter mt-6 space-y-6 rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
          data-testid="academic-result"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-black/10 pb-4">
            <div className="flex items-center gap-2.5">
              {result.verdict === 'authentic' ? (
                <ShieldCheck className="h-5 w-5 text-[#16a34a]" aria-hidden="true" />
              ) : (
                <ShieldAlert className="h-5 w-5 text-[#d97706]" aria-hidden="true" />
              )}
              <h3 className={`text-xl font-medium ${verdictAccent(result.verdict)}`}>
                {t.academic.verdicts[result.verdict]}
              </h3>
            </div>
            <span className="text-xs tabular-nums text-black/55">
              {lang === 'ar'
                ? `${result.word_count} كلمة · ${result.sentence_count} جملة`
                : `${result.word_count} words · ${result.sentence_count} sentences`}
            </span>
          </div>

          {/* Calibrated AI vs Human Origin Banner + Probabilistic Disclaimer */}
          {result.ai_detection ? (
            <div
              className={`rounded-xl border p-4 text-sm ${
                result.ai_detection.classification === 'inconclusive'
                  ? 'border-[#d97706]/35 bg-[#d97706]/10 text-[#78350f]'
                  : result.ai_detection.classification === 'ai_leaning'
                    ? 'border-[#dc2626]/25 bg-[#dc2626]/5 text-[#7f1d1d]'
                    : 'border-[#16a34a]/25 bg-[#16a34a]/5 text-[#14532d]'
              }`}
              data-testid="ai-classification-banner"
            >
              <p className="font-medium">
                {lang === 'ar'
                  ? result.ai_detection.headline_ar
                  : result.ai_detection.headline_en}
              </p>
              <p className="mt-1 text-xs opacity-85">
                {lang === 'ar'
                  ? `اللغة: ${result.ai_detection.language.toUpperCase()} · معامل معايرة النموذج (OOF Brier): ${result.ai_detection.model_oof_brier}`
                  : `Pipeline: ${result.ai_detection.language.toUpperCase()} · Out-of-fold Brier score: ${result.ai_detection.model_oof_brier}`}
              </p>
            </div>
          ) : null}

          {/* Metrics Grid */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: t.academic.originalityLabel, value: `${result.originality_score}%`, className: verdictAccent(result.verdict) },
              {
                label: t.academic.aiProbLabel,
                value: result.ai_probability !== null ? `${result.ai_probability}%` : lang === 'ar' ? 'غير محسوم' : 'Inconclusive',
                className: 'text-black',
                testId: 'ai-probability-value',
              },
              { label: t.academic.plagiarismLabel, value: `${result.plagiarism_pct}%`, className: 'text-black' },
              { label: t.academic.richnessLabel, value: `${Math.round(result.lexical_richness * 100)}%`, className: 'text-black' },
            ].map((card) => (
              <div key={card.label} className="rounded-xl border border-black/10 bg-[#f7f7f5] p-3.5">
                <span className="block text-xs text-black/55">{card.label}</span>
                <span
                  data-testid={card.testId}
                  className={`mt-1 block text-2xl font-medium tabular-nums ${card.className}`}
                >
                  {card.value}
                </span>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-black/10 px-4 py-3 text-sm">
              <span className="block text-xs text-black/55">{t.academic.behaviorLabel}</span>
              <span className="mt-1 block font-medium text-black">
                {t.academic.behaviorStatuses[result.behavior.status]}
              </span>
            </div>
            <div className="rounded-xl border border-black/10 px-4 py-3 text-sm">
              <span className="block text-xs text-black/55">{t.academic.burstinessLabel}</span>
              <span className="mt-1 block font-medium tabular-nums text-black">
                CV = {result.burstiness}
              </span>
            </div>
          </div>

          {result.ai_detection ? (
            <div className="grid grid-cols-2 gap-2.5 text-xs sm:grid-cols-4" data-testid="calibrated-stylometry-metrics">
              {[
                { label: lang === 'ar' ? 'تقريب الحيرة (Perplexity)' : 'Perplexity Proxy', value: result.ai_detection.metrics.perplexity_proxy },
                { label: 'Root-TTR', value: result.ai_detection.metrics.root_ttr },
                { label: 'Hapax Ratio', value: result.ai_detection.metrics.hapax_ratio },
                { label: lang === 'ar' ? 'تنوع الترقيم' : 'Punct. Entropy', value: result.ai_detection.metrics.punctuation_entropy },
              ].map((m) => (
                <div key={m.label} className="rounded-lg border border-black/10 bg-[#f7f7f5] px-3 py-2">
                  <span className="block text-black/55">{m.label}</span>
                  <span className="font-mono font-medium tabular-nums text-black" dir="ltr">
                    {m.value}
                  </span>
                </div>
              ))}
            </div>
          ) : null}

          {result.signals.length > 0 ? (
            <div>
              <h4 className="text-sm font-medium text-black">{t.academic.signalsTitle}</h4>
              <ul className="mt-2.5 space-y-2">
                {result.signals.map((sig, idx) => (
                  <li
                    key={`${sig.title_en}-${idx}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-black/10 bg-[#f7f7f5] px-4 py-2.5 text-sm"
                  >
                    <span className="text-black">
                      {lang === 'ar' ? sig.title_ar : sig.title_en}
                    </span>
                    <span className="font-mono text-xs text-black/55" dir="ltr">
                      {sig.detail}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {result.plagiarism_matches.length > 0 ? (
            <div>
              <h4 className="text-sm font-medium text-[#dc2626]">
                {t.academic.plagiarismMatchesTitle}
              </h4>
              <ul className="mt-2.5 space-y-2">
                {result.plagiarism_matches.map((match) => (
                  <li
                    key={match.source}
                    className="rounded-xl border border-[#dc2626]/20 bg-[#dc2626]/5 px-4 py-3 text-sm"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <strong className="text-black">{match.source}</strong>
                      <span className="tabular-nums font-medium text-[#dc2626]">
                        {match.overlap_pct}%
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-black/65">“{match.sample}”</p>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {/* Blockchain Certificate Issuance Panel */}
          {result.eligible_for_certificate ? (
            <div
              className="rounded-2xl border border-black/15 bg-[#f7f7f5] p-5"
              data-testid="certificate-issuer"
            >
              <div className="flex items-start gap-3">
                <Award className="mt-0.5 h-5 w-5 shrink-0 text-black" aria-hidden="true" />
                <div>
                  <h4 className="text-base font-medium text-black">
                    {t.academic.certEligibleTitle}
                  </h4>
                  <p className="mt-1 text-xs leading-relaxed text-black/65">
                    {t.academic.certEligibleSubtitle}
                  </p>
                </div>
              </div>

              {!issuedCert ? (
                <form onSubmit={handleIssueCertificate} className="mt-4 space-y-3" noValidate>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    {[
                      { id: 'cert-title', label: t.academic.certTitleLabel, value: certTitle, setter: setCertTitle, placeholder: t.academic.certTitlePlaceholder, clearErr: true },
                      { id: 'cert-author', label: t.academic.certAuthorLabel, value: certAuthor, setter: setCertAuthor, placeholder: t.academic.certAuthorPlaceholder, clearErr: true },
                      { id: 'cert-inst', label: t.academic.certInstitutionLabel, value: certInstitution, setter: setCertInstitution, placeholder: t.academic.certInstitutionPlaceholder, clearErr: false },
                    ].map((field) => (
                      <div key={field.id}>
                        <label htmlFor={field.id} className="block text-xs font-medium text-black">
                          {field.label}
                        </label>
                        <input
                          id={field.id}
                          type="text"
                          value={field.value}
                          onChange={(e) => {
                            field.setter(e.target.value);
                            if (field.clearErr) setCertError(null);
                          }}
                          placeholder={field.placeholder}
                          className="mt-1 h-10 w-full rounded-xl border border-black/15 bg-white px-3 text-sm text-black placeholder:text-black/40 focus:border-black focus:outline-none"
                        />
                      </div>
                    ))}
                  </div>

                  {certError ? (
                    <p className="text-xs font-medium text-[#dc2626]" role="alert">
                      {certError}
                    </p>
                  ) : null}

                  <button
                    type="submit"
                    disabled={issuing}
                    className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full bg-black px-5 py-2 text-xs font-medium text-white transition-opacity hover:opacity-85 disabled:opacity-60"
                  >
                    {issuing ? t.academic.issuingCertButton : t.academic.issueCertButton}
                  </button>
                </form>
              ) : (
                <div
                  className="mt-4 rounded-xl border border-black/15 bg-white p-4"
                  data-testid="issued-certificate-card"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-sm font-medium text-[#16a34a]">
                      <FileCheck2 className="h-4 w-4" aria-hidden="true" />
                      <span>{t.academic.certIssuedTitle}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleCopyCertId()}
                      className="inline-flex min-h-8 items-center gap-1.5 rounded-full border border-black/15 bg-[#f7f7f5] px-3 py-1 text-xs font-medium text-black hover:bg-black hover:text-white"
                    >
                      {copiedId ? (
                        <Check className="h-3.5 w-3.5" aria-hidden="true" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                      <span>
                        {copiedId ? t.academic.copiedCertIdButton : t.academic.copyCertIdButton}
                      </span>
                    </button>
                  </div>

                  <dl className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                    {[
                      { label: t.academic.certIdLabel, value: issuedCert.cert_id, cls: 'text-sm font-medium text-black' },
                      { label: t.academic.blockIndexLabel, value: `#${issuedCert.block_index} · ${issuedCert.originality_score}%`, cls: 'text-sm font-medium tabular-nums text-black' },
                      { label: t.academic.blockHashLabel, value: issuedCert.block_hash, cls: 'break-all text-[11px] text-black', wide: true },
                      { label: t.academic.docHashLabel, value: issuedCert.doc_hash, cls: 'break-all text-[11px] text-black/75', wide: true },
                    ].map((row) => (
                      <div key={row.label} className={`rounded-lg bg-[#f7f7f5] px-3 py-2 ${row.wide ? 'sm:col-span-2' : ''}`}>
                        <dt className="text-black/55">{row.label}</dt>
                        <dd className={`mt-0.5 font-mono ${row.cls}`} dir="ltr">
                          {row.value}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </div>
              )}
            </div>
          ) : null}

          {result.ai_detection?.evidence_bundle ? (
            <EvidenceBundlePanel
              bundle={result.ai_detection.evidence_bundle}
              lang={lang}
              hideEvidenceList
            />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

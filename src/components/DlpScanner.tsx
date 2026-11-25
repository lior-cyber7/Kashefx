import { useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import { FileKey2, ShieldAlert, ShieldCheck, Upload } from 'lucide-react';
import type { DlpScanResult, Language } from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';
import { UrlForensicsPanel } from './UrlForensicsPanel';

interface DlpScannerProps {
  lang: Language;
  t: TranslationBundle;
}

export function DlpScanner({ lang, t }: DlpScannerProps) {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DlpScanResult | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);

  const handleFileUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setContent(text.slice(0, 20000));
      setError(null);
    } catch {
      setError(t.hero.networkError);
    } finally {
      e.target.value = '';
    }
  };

  const handleScan = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = content.trim();
    if (!trimmed) {
      setError(t.dlp.emptyError);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await apiJson<DlpScanResult>('/api/dlp/scan', { text: trimmed });
      setResult(data);
    } catch (err) {
      setError(getApiErrorMessage(err, t.hero));
    } finally {
      setLoading(false);
    }
  };

  const verdictColor = (verdict: DlpScanResult['verdict']) => {
    if (verdict === 'safe') return 'text-[#16a34a]';
    if (verdict === 'suspicious') return 'text-[#d97706]';
    return 'text-[#dc2626]';
  };

  return (
    <div className="mt-6 text-start" data-testid="dlp-scanner">
      <form
        onSubmit={handleScan}
        noValidate
        className="rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
      >
        <h2 className="text-lg font-medium text-black">{t.dlp.title}</h2>
        <p className="mt-1 text-sm text-black/65">{t.dlp.subtitle}</p>

        <div className="mt-4 flex items-center justify-between gap-2">
          <label htmlFor="dlp-textarea" className="text-sm font-medium text-black">
            {t.dlp.textLabel}
          </label>
          <span className="text-xs tabular-nums text-black/50">{content.length} / 20000</span>
        </div>

        <textarea
          id="dlp-textarea"
          value={content}
          onChange={(e) => {
            setContent(e.target.value);
            setError(null);
          }}
          placeholder={t.dlp.textPlaceholder}
          rows={6}
          className="mt-2 min-h-[150px] w-full resize-y rounded-2xl border border-black/15 bg-[#f7f7f5] p-4 font-mono text-xs leading-relaxed text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20 sm:text-sm"
        />

        {error ? (
          <p className="mt-3 text-sm font-medium text-[#dc2626]" role="alert">
            {error}
          </p>
        ) : null}

        <div className="mt-4 flex flex-wrap items-center gap-2.5">
          <button
            type="submit"
            disabled={loading}
            className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 disabled:opacity-60"
          >
            {loading ? t.dlp.scanningButton : t.dlp.scanButton}
          </button>

          <input
            ref={fileRef}
            type="file"
            accept=".txt,.md,.json,.csv,.env,.log,text/plain"
            onChange={(e) => void handleFileUpload(e)}
            className="sr-only"
          />
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            className="inline-flex min-h-10 items-center gap-2 whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{t.dlp.uploadFileButton}</span>
          </button>

          <button
            type="button"
            onClick={() => {
              if (!t.dlp.sampleLeak) return;
              setContent(t.dlp.sampleLeak);
              setError(null);
              setResult(null);
            }}
            className="inline-flex min-h-10 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
          >
            {t.dlp.sampleLeakButton}
          </button>
        </div>
      </form>

      {result ? (
        <div
          className="kashf-result-enter mt-6 space-y-5 rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
          data-testid="dlp-result"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-black/10 pb-4">
            <div className="flex items-center gap-2.5">
              {result.verdict === 'safe' ? (
                <ShieldCheck className="h-5 w-5 text-[#16a34a]" aria-hidden="true" />
              ) : (
                <ShieldAlert className="h-5 w-5 text-[#dc2626]" aria-hidden="true" />
              )}
              <div>
                <span className="block text-xs text-black/55">{t.dlp.riskLabel}</span>
                <span className={`text-xl font-medium ${verdictColor(result.verdict)}`}>
                  {t.result.verdicts[result.verdict]}
                </span>
              </div>
            </div>
            <span className="text-3xl font-medium tabular-nums text-black">
              {result.risk_score}/100
            </span>
          </div>

          <div>
            <h3 className="flex items-center gap-2 text-sm font-medium text-black">
              <FileKey2 className="h-4 w-4 text-black/70" aria-hidden="true" />
              <span>{t.dlp.findingsTitle}</span>
            </h3>

            {result.dlp_findings.length === 0 ? (
              <p className="mt-2 rounded-xl border border-black/10 bg-[#f7f7f5] px-4 py-3 text-sm text-[#16a34a]">
                {t.dlp.noSecretsText}
              </p>
            ) : (
              <ul className="mt-2.5 space-y-2">
                {result.dlp_findings.map((finding) => (
                  <li
                    key={`${finding.id}-${finding.masked_value}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-black/10 bg-[#f7f7f5] px-4 py-3 text-sm"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-block h-2 w-2 rounded-full ${
                          finding.severity === 'high' ? 'bg-[#dc2626]' : 'bg-[#d97706]'
                        }`}
                        aria-hidden="true"
                      />
                      <span className="font-medium text-black">
                        {lang === 'ar' ? finding.title_ar : finding.title_en}
                      </span>
                    </div>
                    <code
                      className="rounded border border-black/10 bg-white px-2.5 py-1 font-mono text-xs text-black"
                      dir="ltr"
                    >
                      {finding.masked_value}
                    </code>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {result.url_forensics.length > 0 ? (
            <div className="space-y-4">
              <h3 className="text-sm font-medium text-black">{t.dlp.urlsTitle}</h3>
              {result.url_forensics.map((uf) => (
                <UrlForensicsPanel key={uf.original_url} forensics={uf} lang={lang} t={t} />
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

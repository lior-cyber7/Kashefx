import { useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import type { BatchAnalysisResult, Verdict } from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';

interface BatchScannerProps {
  t: TranslationBundle;
  onInspectMessage: (text: string) => void;
}

const VERDICT_BADGE_CLASS: Record<Verdict, string> = {
  safe: 'text-[#16a34a]',
  suspicious: 'text-[#d97706]',
  dangerous: 'text-[#dc2626]',
};

export function BatchScanner({ t, onInspectMessage }: BatchScannerProps) {
  const [rawInput, setRawInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<BatchAnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const content = await file.text();
      setRawInput(content.slice(0, 25000));
      setError(null);
    } catch {
      setError(t.hero.networkError);
    } finally {
      e.target.value = '';
    }
  };

  const handleLoadSample = () => {
    setRawInput(t.batch.placeholder);
    setError(null);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!rawInput.trim()) {
      setError(t.batch.emptyError);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await apiJson<BatchAnalysisResult>('/api/analyze-batch', {
        raw_text: rawInput.slice(0, 25000),
      });
      setBatchResult(data);
    } catch (err) {
      setError(getApiErrorMessage(err, t.hero));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mt-6 text-start" data-testid="batch-scanner">
      <form
        onSubmit={handleSubmit}
        noValidate
        className="rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
      >
        <h2 className="text-lg font-medium text-black">{t.batch.title}</h2>
        <p className="mt-1 text-sm text-black/65">{t.batch.subtitle}</p>

        <textarea
          value={rawInput}
          onChange={(e) => {
            setRawInput(e.target.value);
            setError(null);
          }}
          placeholder={t.batch.placeholder}
          rows={6}
          aria-label={t.batch.title}
          className="mt-4 min-h-[160px] w-full resize-y rounded-2xl border border-black/15 bg-[#f7f7f5] p-4 text-sm leading-relaxed text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20"
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
            className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
          >
            {loading ? t.batch.scanningButton : t.batch.scanButton}
          </button>

          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,text/plain"
            onChange={(e) => void handleFileUpload(e)}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
          >
            {t.batch.uploadTxtButton}
          </button>

          <button
            type="button"
            onClick={handleLoadSample}
            className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
          >
            {t.batch.sampleButton}
          </button>
        </div>
      </form>

      {batchResult ? (
        <div className="kashf-result-enter mt-6 space-y-4" data-testid="batch-results">
          {/* 4-column summary KPI strip */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: t.batch.totalLabel, value: batchResult.total, color: 'text-black' },
              { label: t.batch.dangerousLabel, value: batchResult.dangerous_count, color: 'text-[#dc2626]' },
              { label: t.batch.suspiciousLabel, value: batchResult.suspicious_count, color: 'text-[#d97706]' },
              { label: t.batch.safeLabel, value: batchResult.safe_count, color: 'text-[#16a34a]' },
            ].map((kpi) => (
              <div key={kpi.label} className="rounded-xl border border-black/10 bg-white p-4">
                <span className="block text-xs text-black/55">{kpi.label}</span>
                <span className={`mt-1 block text-2xl font-medium tabular-nums ${kpi.color}`}>
                  {kpi.value}
                </span>
              </div>
            ))}
          </div>

          {/* Ranked message list */}
          <div className="divide-y divide-black/10 rounded-2xl border border-black/10 bg-white">
            {batchResult.items.map((item) => (
              <div
                key={item.index}
                className="flex flex-col justify-between gap-3 p-4 sm:flex-row sm:items-center sm:p-5"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-black/60">
                    <span className={`font-medium ${VERDICT_BADGE_CLASS[item.result.verdict]}`}>
                      {t.result.verdicts[item.result.verdict]}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="tabular-nums">{item.result.score}/100</span>
                    <span aria-hidden="true">·</span>
                    <span>{t.categories[item.result.category] ?? t.categories.other}</span>
                  </div>
                  <p className="mt-1.5 text-sm leading-relaxed text-black break-words">
                    {item.preview}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onInspectMessage(item.text)}
                  className="inline-flex min-h-9 shrink-0 items-center justify-center self-start whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black sm:self-center"
                >
                  {t.batch.inspectSingleButton}
                </button>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

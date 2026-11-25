import { useState, type FormEvent } from 'react';
import type { Language, LiveUrlProbeResult } from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';
import { UrlForensicsPanel } from './UrlForensicsPanel';

interface UrlLabProps {
  lang: Language;
  t: TranslationBundle;
  onOpenSandbox?: (url: string) => void;
}

export function UrlLab({ lang, t, onOpenSandbox }: UrlLabProps) {
  const [urlValue, setUrlValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<LiveUrlProbeResult | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = urlValue.trim();
    if (trimmed.length < 3) {
      setError(t.urlLab.emptyError);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await apiJson<LiveUrlProbeResult>('/api/inspect-url', { url: trimmed });
      setProbeResult(data);
    } catch (err) {
      setError(getApiErrorMessage(err, t.hero));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mt-6 text-start" data-testid="url-lab">
      <form
        onSubmit={handleSubmit}
        noValidate
        className="rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
      >
        <h2 className="text-lg font-medium text-black">{t.urlLab.title}</h2>
        <p className="mt-1 text-sm text-black/65">{t.urlLab.subtitle}</p>

        <label
          htmlFor="url-lab-input"
          className="mt-4 block text-sm font-medium text-black"
        >
          {t.urlLab.inputLabel}
        </label>
        <input
          id="url-lab-input"
          type="url"
          dir="ltr"
          value={urlValue}
          onChange={(e) => {
            setUrlValue(e.target.value);
            setError(null);
          }}
          placeholder={t.urlLab.placeholder}
          className="mt-2 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-4 font-mono text-sm text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20"
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
            {loading ? t.urlLab.inspectingButton : t.urlLab.inspectButton}
          </button>

          <button
            type="button"
            onClick={() => {
              setUrlValue('http://paypa1-secure.xyz/login?utm_source=sms&redirect=https://evil.com');
              setError(null);
            }}
            className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
          >
            paypa1-secure.xyz
          </button>

          <button
            type="button"
            onClick={() => {
              setUrlValue('https://example.com');
              setError(null);
            }}
            className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
          >
            example.com
          </button>
        </div>
      </form>

      {probeResult ? (
        <div
          key={probeResult.forensics.original_url + probeResult.final_url}
          className="kashf-result-enter mt-6 rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
          data-testid="url-lab-result"
        >
          <UrlForensicsPanel
            forensics={probeResult.forensics}
            lang={lang}
            t={t}
            initialProbe={probeResult}
            onOpenSandbox={onOpenSandbox}
          />
        </div>
      ) : null}
    </div>
  );
}

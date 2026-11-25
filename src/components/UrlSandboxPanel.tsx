import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Eye, Lock, ShieldAlert, ShieldCheck, Terminal } from 'lucide-react';
import type { Language, UrlSandboxResult } from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';

interface UrlSandboxPanelProps {
  lang: Language;
  t: TranslationBundle;
  initialUrl?: string;
  autoRunKey?: number;
}

export function UrlSandboxPanel({
  lang,
  t,
  initialUrl = '',
  autoRunKey = 0,
}: UrlSandboxPanelProps) {
  const [urlValue, setUrlValue] = useState(initialUrl);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UrlSandboxResult | null>(null);

  const detonate = useCallback(
    async (targetUrl: string) => {
      const trimmed = targetUrl.trim();
      if (trimmed.length < 3) {
        setError(t.urlSandbox.emptyError);
        return;
      }

      setLoading(true);
      setError(null);
      try {
        const data = await apiJson<UrlSandboxResult>('/api/sandbox-url', { url: trimmed });
        setResult(data);
      } catch (err) {
        setError(getApiErrorMessage(err, t.hero));
      } finally {
        setLoading(false);
      }
    },
    [t.hero, t.urlSandbox.emptyError],
  );

  useEffect(() => {
    if (autoRunKey > 0 && initialUrl.trim().length >= 3) {
      setUrlValue(initialUrl);
      void detonate(initialUrl);
    }
  }, [autoRunKey, initialUrl, detonate]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void detonate(urlValue);
  };

  const verdictColor = (v: UrlSandboxResult['verdict']) => {
    if (v === 'safe') return 'text-[#16a34a]';
    if (v === 'suspicious') return 'text-[#d97706]';
    return 'text-[#dc2626]';
  };

  const severityDot = (sev: 'high' | 'medium' | 'low' | 'safe') => {
    if (sev === 'high') return 'bg-[#dc2626]';
    if (sev === 'medium') return 'bg-[#d97706]';
    if (sev === 'safe') return 'bg-[#16a34a]';
    return 'bg-black/45';
  };

  return (
    <div className="mt-6 text-start" data-testid="url-sandbox-panel">
      <form
        onSubmit={handleSubmit}
        noValidate
        className="rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-medium text-black">{t.urlSandbox.title}</h2>
            <p className="mt-1 max-w-3xl text-sm text-black/65">{t.urlSandbox.subtitle}</p>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-2 rounded-xl border border-[#16a34a]/25 bg-[#16a34a]/5 px-3.5 py-2.5 text-xs text-black/80">
          <Lock className="h-4 w-4 shrink-0 text-[#16a34a]" aria-hidden="true" />
          <span>{t.urlSandbox.isolationNotice}</span>
        </div>

        <label
          htmlFor="url-sandbox-input"
          className="mt-4 block text-sm font-medium text-black"
        >
          {t.urlSandbox.inputLabel}
        </label>
        <input
          id="url-sandbox-input"
          type="url"
          dir="ltr"
          value={urlValue}
          onChange={(e) => {
            setUrlValue(e.target.value);
            setError(null);
          }}
          placeholder={t.urlSandbox.placeholder}
          className="mt-2 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-4 font-mono text-sm text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20"
        />

        {error ? (
          <p className="mt-3 text-sm font-medium text-[#dc2626]" role="alert">
            {error}
          </p>
        ) : null}

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button
            type="submit"
            disabled={loading}
            data-testid="sandbox-detonate-btn"
            className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 disabled:opacity-60"
          >
            {loading ? t.urlSandbox.runningButton : t.urlSandbox.runButton}
          </button>

          <button
            type="button"
            onClick={() => {
              const sample = 'http://paypa1-secure.xyz/login?otp=required';
              setUrlValue(sample);
              void detonate(sample);
            }}
            className="inline-flex min-h-10 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
          >
            {t.urlSandbox.presetPhishLabel}
          </button>

          <button
            type="button"
            onClick={() => {
              const sample = 'https://updates-portal.top/app-update.apk';
              setUrlValue(sample);
              void detonate(sample);
            }}
            className="inline-flex min-h-10 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
          >
            {t.urlSandbox.presetApkLabel}
          </button>

          <button
            type="button"
            onClick={() => {
              const sample = 'https://example.com';
              setUrlValue(sample);
              void detonate(sample);
            }}
            className="inline-flex min-h-10 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
          >
            {t.urlSandbox.presetSafeLabel}
          </button>
        </div>
      </form>

      {result ? (
        <div
          className="kashf-result-enter mt-6 space-y-6 rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
          data-testid="sandbox-detonation-result"
        >
          {/* Header Verdict */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-black/10 pb-4">
            <div className="flex items-center gap-3">
              {result.verdict === 'safe' ? (
                <ShieldCheck className="h-6 w-6 shrink-0 text-[#16a34a]" aria-hidden="true" />
              ) : (
                <ShieldAlert className="h-6 w-6 shrink-0 text-[#dc2626]" aria-hidden="true" />
              )}
              <div>
                <span className="block text-xs text-black/55">
                  {t.urlSandbox.modeLabels[result.execution_mode]}
                </span>
                <h3 className={`text-xl font-medium ${verdictColor(result.verdict)}`}>
                  {t.result.verdicts[result.verdict]}
                </h3>
              </div>
            </div>
            <div className="text-end">
              <span className="text-3xl font-medium tabular-nums text-black">
                {result.sandbox_score}/100
              </span>
            </div>
          </div>

          {/* What This Link Would Do If Opened */}
          <div>
            <h4 className="flex items-center gap-2 text-base font-medium text-black">
              <Terminal className="h-4 w-4 text-black/70" aria-hidden="true" />
              <span>{t.urlSandbox.whatTitle}</span>
            </h4>

            <ul className="mt-3 space-y-2.5" data-testid="sandbox-actions-list">
              {result.what_it_tries_to_do.map((action, idx) => (
                <li
                  key={`${action.id}-${idx}`}
                  className="rounded-xl border border-black/10 bg-[#f7f7f5] p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-block h-2 w-2 shrink-0 rounded-full ${severityDot(action.severity)}`}
                        aria-hidden="true"
                      />
                      <strong className="text-sm font-medium text-black">
                        {lang === 'ar' ? action.title_ar : action.title_en}
                      </strong>
                    </div>
                    <span className="text-[11px] font-medium text-black/55">
                      {action.observed
                        ? t.urlSandbox.observedTag
                        : t.urlSandbox.predictedTag}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-black/70">
                    {lang === 'ar' ? action.detail_ar : action.detail_en}
                  </p>
                </li>
              ))}
            </ul>
          </div>

          {/* Inert Zero-Execution Browser Preview Frame */}
          <div className="rounded-2xl border border-black/15 bg-[#f7f7f5] p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-black/10">
              <div className="flex items-center gap-2">
                <Eye className="h-4 w-4 text-black/70" aria-hidden="true" />
                <div>
                  <h4 className="text-sm font-medium text-black">
                    {t.urlSandbox.previewTitle}
                  </h4>
                  <p className="text-[11px] text-black/55">{t.urlSandbox.previewSubtitle}</p>
                </div>
              </div>
              <span className="font-mono text-[11px] text-[#16a34a]" dir="ltr">
                JS: OFF · COOKIES: 0 · FS: READONLY
              </span>
            </div>

            <div className="mt-3 rounded-xl border border-black/10 bg-white overflow-hidden">
              {/* Mock inert browser address bar */}
              <div className="flex items-center justify-between gap-2 border-b border-black/10 bg-[#f4f4f2] px-3 py-2 text-xs">
                <code className="truncate font-mono text-black" dir="ltr">
                  {result.network_trace.final_url || result.defanged_url}
                </code>
                {result.dom_telemetry.page_title ? (
                  <span className="truncate text-[11px] text-black/60">
                    {result.dom_telemetry.page_title}
                  </span>
                ) : null}
              </div>

              <div className="p-4 text-xs space-y-3">
                {result.dom_telemetry.sensitive_inputs.length > 0 ? (
                  <div className="rounded-lg border border-[#dc2626]/25 bg-[#dc2626]/5 p-3">
                    <span className="block font-medium text-[#dc2626]">
                      {t.urlSandbox.previewTrapWarning}
                    </span>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {result.dom_telemetry.sensitive_inputs.map((field) => (
                        <span
                          key={field}
                          className="rounded border border-black/15 bg-white px-2.5 py-1 font-mono text-[11px] text-black"
                          dir="ltr"
                        >
                          [input: {field}]
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                <p className="leading-relaxed text-black/75">
                  {result.dom_telemetry.visible_text_preview || t.urlSandbox.previewEmptyText}
                </p>
              </div>
            </div>
          </div>

          {/* HTTP & DOM Telemetry Grid */}
          <div>
            <h4 className="text-sm font-medium text-black">{t.urlSandbox.telemetryTitle}</h4>
            <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              {[
                { label: t.urlSandbox.httpStatusLabel, value: result.network_trace.http_status ?? 'Offline' },
                { label: t.urlSandbox.formsLabel, value: `${result.dom_telemetry.forms_count} / ${result.dom_telemetry.password_inputs}` },
                { label: t.urlSandbox.scriptsLabel, value: `${result.dom_telemetry.scripts_count} / ${result.dom_telemetry.obfuscated_js_hits}` },
                { label: t.urlSandbox.iframesLabel, value: result.dom_telemetry.hidden_iframes_count },
                { label: t.urlSandbox.cookiesLabel, value: result.network_trace.cookies_attempted },
                { label: t.urlSandbox.contentTypeLabel, value: result.network_trace.content_type?.split(';')[0] || '—', truncate: true },
              ].map((stat) => (
                <div key={stat.label} className="rounded-xl border border-black/10 bg-[#f7f7f5] p-3">
                  <span className="block text-[11px] text-black/55">{stat.label}</span>
                  <span
                    className={`mt-1 block font-mono text-black ${stat.truncate ? 'truncate text-xs' : 'text-sm font-medium tabular-nums'}`}
                    dir="ltr"
                  >
                    {stat.value}
                  </span>
                </div>
              ))}
            </div>

            {result.network_trace.redirects.length > 0 ? (
              <div className="mt-4 rounded-xl border border-black/10 bg-[#f7f7f5] p-3.5 text-xs">
                <span className="font-medium text-black">{t.urlSandbox.redirectsTitle}</span>
                <ol className="mt-1.5 space-y-1 font-mono text-[11px] text-black/75" dir="ltr">
                  {result.network_trace.redirects.map((hop, idx) => (
                    <li key={idx} className="truncate">
                      [{hop.status}] {hop.url}
                    </li>
                  ))}
                </ol>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

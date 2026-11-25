import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import type {
  CommunityStats,
  Language,
  LocalHistoryItem,
  TrendingItem,
} from './types';
import { BOOT_I18N, fetchI18nBundles } from './i18n';
import { apiJson } from './utils/api';
import {
  MAX_MESSAGE_LENGTH,
  enforceMaxLength,
  extractUrlsFromText,
} from './utils/urlDetect';
import { useAnalyze } from './hooks/useAnalyze';
import { BackgroundVideo } from './components/BackgroundVideo';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { ResultCard } from './components/ResultCard';
import { TrendingSection } from './components/TrendingSection';
import { LearnSection } from './components/LearnSection';
import { Footer } from './components/Footer';
import { BatchScanner } from './components/BatchScanner';
import { UrlLab } from './components/UrlLab';
import { ScanHistory } from './components/ScanHistory';
import { PhishingQuiz } from './components/PhishingQuiz';
import { AcademicShield } from './components/AcademicShield';
import { DlpScanner } from './components/DlpScanner';
import { UrlSandboxPanel } from './components/UrlSandboxPanel';

type AnalyzerTab = 'single' | 'batch' | 'url' | 'sandbox' | 'academic' | 'dlp' | 'history';

const HISTORY_STORAGE_KEY = 'kashf_scan_history_v1';

function loadLocalHistory(): LocalHistoryItem[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as LocalHistoryItem[]).slice(0, 12) : [];
  } catch {
    return [];
  }
}

export default function App() {
  const [lang, setLang] = useState<Language>('ar');
  const [bundles, setBundles] = useState(BOOT_I18N);
  const [activeTab, setActiveTab] = useState<AnalyzerTab>('single');
  const [messageText, setMessageText] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [urlManuallyEdited, setUrlManuallyEdited] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [truncatedWarning, setTruncatedWarning] = useState(false);

  const [history, setHistory] = useState<LocalHistoryItem[]>(() => loadLocalHistory());

  const [trendingItems, setTrendingItems] = useState<TrendingItem[]>([]);
  const [trendingStats, setTrendingStats] = useState<CommunityStats | null>(null);
  const [trendingLoading, setTrendingLoading] = useState(true);
  const [trendingError, setTrendingError] = useState(false);
  const [sandboxUrl, setSandboxUrl] = useState('');
  const [sandboxTriggerKey, setSandboxTriggerKey] = useState(0);

  const analyzerSectionRef = useRef<HTMLElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const t = bundles[lang];

  const {
    loading,
    error: apiError,
    result,
    analyzedText,
    reporting,
    reported,
    reportError,
    analyze,
    reportResult,
    clearError,
    resetResult,
  } = useAnalyze(t);

  useEffect(() => {
    let cancelled = false;
    fetchI18nBundles()
      .then((data) => {
        if (!cancelled && data?.ar && data?.en) {
          setBundles(data);
        }
      })
      .catch(() => {
        // Keep BOOT_I18N defaults if backend i18n endpoint is momentarily unavailable
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const html = document.documentElement;
    html.lang = lang;
    html.dir = lang === 'ar' ? 'rtl' : 'ltr';
  }, [lang]);

  // Save completed single analyses to browser-only localStorage history
  useEffect(() => {
    if (!result || !analyzedText) return;
    setHistory((prev) => {
      const nextItem: LocalHistoryItem = {
        id: `${result.fingerprint}-${Date.now()}`,
        timestamp: Date.now(),
        preview: analyzedText.slice(0, 120) + (analyzedText.length > 120 ? '...' : ''),
        text: analyzedText,
        score: result.score,
        verdict: result.verdict,
        category: result.category,
      };
      const filtered = prev.filter((item) => item.text !== analyzedText);
      const updated = [nextItem, ...filtered].slice(0, 12);
      try {
        localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // Ignore storage quota issues
      }
      return updated;
    });
  }, [result, analyzedText]);

  const fetchTrending = useCallback(async () => {
    setTrendingLoading(true);
    setTrendingError(false);
    try {
      const data = await apiJson<{
        items?: TrendingItem[];
        stats?: CommunityStats | null;
      }>('/api/trending');
      setTrendingItems(Array.isArray(data.items) ? data.items : []);
      setTrendingStats(data.stats ?? null);
    } catch {
      setTrendingError(true);
    } finally {
      setTrendingLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchTrending();
  }, [fetchTrending]);

  const detectedUrls = extractUrlsFromText(messageText);

  const handleTextChange = (raw: string) => {
    const { value, truncated } = enforceMaxLength(raw, MAX_MESSAGE_LENGTH);
    setMessageText(value);
    setTruncatedWarning(truncated);
    setValidationError(null);
    if (apiError) clearError();

    const urls = extractUrlsFromText(value);
    if (!urlManuallyEdited) {
      setUrlInput(urls[0] ?? '');
    }
  };

  const handleUrlChange = (val: string) => {
    setUrlInput(val);
    setUrlManuallyEdited(val.trim().length > 0);
    setValidationError(null);
    if (apiError) clearError();
  };

  const scrollToAnalyzerAndFocus = () => {
    setActiveTab('single');
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    analyzerSectionRef.current?.scrollIntoView({
      behavior: prefersReduced ? 'auto' : 'smooth',
      block: 'start',
    });
    setTimeout(() => {
      textareaRef.current?.focus();
    }, 250);
  };

  const handleExampleClick = (exampleText: string, shouldScroll: boolean = false) => {
    setActiveTab('single');
    const { value, truncated } = enforceMaxLength(exampleText, MAX_MESSAGE_LENGTH);
    setMessageText(value);
    setTruncatedWarning(truncated);
    setValidationError(null);
    clearError();
    const urls = extractUrlsFromText(value);
    setUrlManuallyEdited(false);
    setUrlInput(urls[0] ?? '');
    if (shouldScroll) {
      scrollToAnalyzerAndFocus();
    }
  };

  const handleInspectInSingle = (text: string) => {
    const { value, truncated } = enforceMaxLength(text, MAX_MESSAGE_LENGTH);
    setActiveTab('single');
    setMessageText(value);
    setTruncatedWarning(truncated);
    setValidationError(null);
    clearError();
    const urls = extractUrlsFromText(value);
    setUrlManuallyEdited(false);
    const firstUrl = urls[0] ?? '';
    setUrlInput(firstUrl);
    void analyze(value, firstUrl);
  };

  const handleClear = () => {
    setMessageText('');
    setUrlInput('');
    setUrlManuallyEdited(false);
    setValidationError(null);
    setTruncatedWarning(false);
    resetResult();
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
      // Ignore
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmedText = messageText.trim();
    const trimmedUrl = urlInput.trim();

    if (!trimmedText && !trimmedUrl) {
      setValidationError(t.hero.emptyError);
      return;
    }

    setValidationError(null);
    const effectiveText = trimmedText || trimmedUrl;
    await analyze(effectiveText, trimmedUrl);
  };

  const handleRetry = () => {
    const trimmedText = messageText.trim();
    const trimmedUrl = urlInput.trim();
    const effectiveText = trimmedText || trimmedUrl;
    if (effectiveText) {
      void analyze(effectiveText, trimmedUrl);
    }
  };

  const handleReportAndRefresh = async (): Promise<boolean> => {
    const ok = await reportResult();
    if (ok) {
      void fetchTrending();
    }
    return ok;
  };

  const handleOpenSandbox = (url: string) => {
    setSandboxUrl(url);
    setSandboxTriggerKey((k) => k + 1);
    setActiveTab('sandbox');
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    analyzerSectionRef.current?.scrollIntoView({
      behavior: prefersReduced ? 'auto' : 'smooth',
      block: 'start',
    });
  };

  const resultRef = useCallback((node: HTMLDivElement | null) => {
    if (!node) return;
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    node.scrollIntoView({
      behavior: prefersReduced ? 'auto' : 'smooth',
      block: 'start',
    });
  }, []);

  const handleToggleLang = () => {
    setLang((prev) => (prev === 'ar' ? 'en' : 'ar'));
  };

  const tabs: Array<{ id: AnalyzerTab; label: string }> = [
    { id: 'single', label: t.hero.tabs.single },
    { id: 'batch', label: t.hero.tabs.batch },
    { id: 'url', label: t.hero.tabs.urlInspector },
    { id: 'sandbox', label: t.hero.tabs.sandbox },
    { id: 'academic', label: t.hero.tabs.academic },
    { id: 'dlp', label: t.hero.tabs.dlp },
    {
      id: 'history',
      label:
        history.length > 0
          ? `${t.hero.tabs.history} (${history.length})`
          : t.hero.tabs.history,
    },
  ];

  return (
    <div className="relative min-h-[100svh] text-black">
      <BackgroundVideo lang={lang} />
      <Navbar lang={lang} t={t} onToggleLang={handleToggleLang} />

      <main className="relative z-[1]">
        {/* Full-screen Mainframe-inspired Hero */}
        <HeroSection
          t={t}
          onStartAnalyze={scrollToAnalyzerAndFocus}
          onSelectExample={(text) => handleExampleClick(text, true)}
        />

        {/* Workspace below hero with crisp light frosted editorial surface */}
        <div className="relative z-[1] border-t border-black/10 bg-white/90 backdrop-blur-md">
          <div className="mx-auto max-w-5xl px-5 pt-14 pb-8 sm:px-8">
            <section
              ref={analyzerSectionRef}
              id="analyzer"
              aria-labelledby="analyzer-heading"
              className="scroll-mt-24 text-start"
            >
              <h1
                id="analyzer-heading"
                className="max-w-3xl text-3xl font-medium leading-tight text-black sm:text-4xl"
                style={{ fontFamily: 'var(--font-heading)', textWrap: 'balance' }}
              >
                {t.hero.headline}
              </h1>
              <p className="mt-3 max-w-2xl text-base leading-relaxed text-black/70">
                {t.hero.subtitle}
              </p>

              {/* Workspace segmented tabs */}
              <div
                role="tablist"
                aria-label={t.hero.headline}
                className="mt-6 inline-flex max-w-full flex-wrap items-center gap-1 rounded-xl border border-black/10 bg-[#f4f4f2] p-1"
              >
                {tabs.map((tab) => {
                  const isActive = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={isActive}
                      onClick={() => setActiveTab(tab.id)}
                      className={`min-h-9 whitespace-nowrap rounded-lg px-3.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black sm:text-sm ${
                        isActive
                          ? 'bg-white text-black shadow-sm'
                          : 'text-black/65 hover:text-black'
                      }`}
                    >
                      {tab.label}
                    </button>
                  );
                })}
              </div>

              {activeTab === 'single' ? (
                <>
                  <form
                    onSubmit={handleSubmit}
                    noValidate
                    className="mt-6 rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-3">
                        <label
                          htmlFor="message-textarea"
                          className="text-sm font-medium text-black"
                        >
                          {t.hero.messageLabel}
                        </label>
                        <span className="text-xs tabular-nums text-black/50">
                          {messageText.length} / {MAX_MESSAGE_LENGTH}
                        </span>
                      </div>

                      <textarea
                        ref={textareaRef}
                        id="message-textarea"
                        value={messageText}
                        onChange={(e) => handleTextChange(e.target.value)}
                        placeholder={t.hero.placeholder}
                        rows={5}
                        className="mt-2.5 min-h-[160px] w-full resize-y rounded-2xl border border-black/15 bg-[#f7f7f5] p-4 text-base leading-relaxed text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20"
                      />

                      {truncatedWarning ? (
                        <p className="mt-2 text-xs text-[#d97706]" role="status">
                          {t.hero.truncatedWarning}
                        </p>
                      ) : null}

                      {detectedUrls.length > 0 ? (
                        <div className="mt-3 flex flex-wrap items-center gap-2">
                          <span className="text-xs text-black/55">
                            {t.hero.detectedUrlsLabel}
                          </span>
                          {detectedUrls.map((detected) => (
                            <button
                              key={detected}
                              type="button"
                              onClick={() => {
                                setUrlInput(detected);
                                setUrlManuallyEdited(true);
                              }}
                              className="inline-flex max-w-full items-center gap-1.5 truncate rounded-full border border-black/15 bg-[#f7f7f5] px-3 py-1 font-mono text-xs text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
                            >
                              <span className="truncate" dir="ltr">
                                {detected}
                              </span>
                            </button>
                          ))}
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4">
                      <label
                        htmlFor="url-input"
                        className="block text-sm font-medium text-black"
                      >
                        {t.hero.urlLabel}
                      </label>
                      <input
                        id="url-input"
                        type="url"
                        dir="ltr"
                        value={urlInput}
                        onChange={(e) => handleUrlChange(e.target.value)}
                        placeholder={t.hero.urlPlaceholder}
                        className="mt-2 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-4 font-mono text-sm text-black placeholder:text-black/40 focus:border-black focus:outline-none focus-visible:ring-2 focus-visible:ring-black/20"
                      />
                    </div>

                    {validationError ? (
                      <div
                        role="alert"
                        className="mt-4 text-sm font-medium text-[#dc2626]"
                      >
                        {validationError}
                      </div>
                    ) : null}

                    {apiError ? (
                      <div
                        role="alert"
                        className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#dc2626]/30 bg-[#dc2626]/10 px-4 py-3 text-sm text-[#7f1d1d]"
                      >
                        <span>{apiError}</span>
                        <button
                          type="button"
                          onClick={handleRetry}
                          className="inline-flex min-h-9 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1 text-xs font-medium text-black hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
                        >
                          {t.hero.retryButton}
                        </button>
                      </div>
                    ) : null}

                    <div className="mt-5 flex flex-wrap items-center gap-3">
                      <button
                        type="submit"
                        disabled={loading}
                        className="inline-flex min-h-11 items-center justify-center gap-2 whitespace-nowrap rounded-full bg-black px-7 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <span>
                          {loading ? t.hero.analyzingButton : t.hero.analyzeButton}
                        </span>
                      </button>

                      {messageText || urlInput || result ? (
                        <button
                          type="button"
                          onClick={handleClear}
                          className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-5 py-2.5 text-sm text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
                        >
                          {t.hero.clearButton}
                        </button>
                      ) : null}
                    </div>
                  </form>

                  <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {t.hero.examples.map((ex) => (
                        <button
                          key={ex.id}
                          type="button"
                          onClick={() => handleExampleClick(ex.text, false)}
                          className="min-h-9 whitespace-nowrap rounded-full border border-black/10 bg-white px-4 py-1 text-xs text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
                        >
                          {ex.label}
                        </button>
                      ))}
                    </div>

                    <p className="text-xs text-black/60">{t.hero.privacyNote}</p>
                  </div>

                  {/* Analysis Result */}
                  {result ? (
                    <div
                      ref={resultRef}
                      key={result.fingerprint + '-' + result.score}
                      className="scroll-mt-24"
                    >
                      <ResultCard
                        result={result}
                        analyzedText={analyzedText}
                        lang={lang}
                        t={t}
                        reporting={reporting}
                        reported={reported}
                        reportError={reportError}
                        onReport={handleReportAndRefresh}
                        onOpenSandbox={handleOpenSandbox}
                      />
                    </div>
                  ) : null}
                </>
              ) : activeTab === 'batch' ? (
                <BatchScanner t={t} onInspectMessage={handleInspectInSingle} />
              ) : activeTab === 'url' ? (
                <UrlLab lang={lang} t={t} onOpenSandbox={handleOpenSandbox} />
              ) : activeTab === 'sandbox' ? (
                <UrlSandboxPanel
                  lang={lang}
                  t={t}
                  initialUrl={sandboxUrl}
                  autoRunKey={sandboxTriggerKey}
                />
              ) : activeTab === 'academic' ? (
                <AcademicShield lang={lang} t={t} />
              ) : activeTab === 'dlp' ? (
                <DlpScanner lang={lang} t={t} />
              ) : (
                <ScanHistory
                  t={t}
                  items={history}
                  onReopen={handleInspectInSingle}
                  onClearAll={handleClearHistory}
                />
              )}
            </section>

            {/* Trending Scams */}
            <TrendingSection
              t={t}
              items={trendingItems}
              stats={trendingStats}
              loading={trendingLoading}
              error={trendingError}
              onRefresh={() => void fetchTrending()}
            />

            {/* Phishing IQ Lab */}
            <PhishingQuiz lang={lang} t={t} />

            {/* Learn */}
            <LearnSection t={t} />
          </div>

          <Footer t={t} />
        </div>
      </main>
    </div>
  );
}

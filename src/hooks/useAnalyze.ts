import { useCallback, useState } from 'react';
import type { AnalysisResult } from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';

interface UseAnalyzeReturn {
  loading: boolean;
  error: string | null;
  result: AnalysisResult | null;
  analyzedText: string;
  reporting: boolean;
  reported: boolean;
  reportError: string | null;
  analyze: (text: string, url?: string) => Promise<void>;
  reportResult: () => Promise<boolean>;
  clearError: () => void;
  resetResult: () => void;
}

export function useAnalyze(t: TranslationBundle): UseAnalyzeReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analyzedText, setAnalyzedText] = useState('');
  const [reporting, setReporting] = useState(false);
  const [reported, setReported] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const analyze = useCallback(
    async (text: string, url?: string) => {
      setLoading(true);
      setError(null);
      setReported(false);
      setReportError(null);

      try {
        const data = await apiJson<AnalysisResult>('/api/analyze', {
          text,
          url: url?.trim() ? url.trim() : null,
        });
        setResult(data);
        setAnalyzedText(text);
      } catch (err) {
        setError(getApiErrorMessage(err, t.hero));
        setResult(null);
      } finally {
        setLoading(false);
      }
    },
    [t.hero],
  );

  const reportResult = useCallback(async (): Promise<boolean> => {
    if (!result || reported || reporting) return false;
    setReporting(true);
    setReportError(null);

    try {
      await apiJson('/api/report', {
        category: result.category,
        score: result.score,
        fingerprint: result.fingerprint,
      });
      setReported(true);
      return true;
    } catch {
      setReportError(t.result.reportError);
      return false;
    } finally {
      setReporting(false);
    }
  }, [reported, reporting, result, t.result.reportError]);

  const clearError = useCallback(() => setError(null), []);
  const resetResult = useCallback(() => {
    setResult(null);
    setAnalyzedText('');
    setReported(false);
    setReportError(null);
    setError(null);
  }, []);

  return {
    loading,
    error,
    result,
    analyzedText,
    reporting,
    reported,
    reportError,
    analyze,
    reportResult,
    clearError,
    resetResult,
  };
}

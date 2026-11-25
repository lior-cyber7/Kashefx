import { useCallback, useEffect, useState } from 'react';
import { Award, CheckCircle2 } from 'lucide-react';
import type { Language, QuizScenario, QuizVerifyResult } from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';

interface PhishingQuizProps {
  lang: Language;
  t: TranslationBundle;
}

type BadgeId = 'first_catch' | 'streak_three' | 'cyber_defender' | 'perfect_shield';

const BADGES_STORAGE_KEY = 'kashf_quiz_badges_v1';

function loadSavedBadges(): BadgeId[] {
  try {
    const raw = localStorage.getItem(BADGES_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as BadgeId[]) : [];
  } catch {
    return [];
  }
}

export function PhishingQuiz({ lang, t }: PhishingQuizProps) {
  const [scenarios, setScenarios] = useState<QuizScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [correctCount, setCorrectCount] = useState(0);
  const [streak, setStreak] = useState(0);
  const [unlockedBadges, setUnlockedBadges] = useState<BadgeId[]>(() => loadSavedBadges());
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<QuizVerifyResult | null>(null);
  const [finished, setFinished] = useState(false);

  const unlockBadges = (newIds: BadgeId[]) => {
    if (newIds.length === 0) return;
    setUnlockedBadges((prev) => {
      const merged = Array.from(new Set([...prev, ...newIds]));
      if (merged.length !== prev.length) {
        try {
          localStorage.setItem(BADGES_STORAGE_KEY, JSON.stringify(merged));
        } catch {
          // Ignore storage quota errors
        }
      }
      return merged;
    });
  };

  const loadQuiz = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const data = await apiJson<{ scenarios?: QuizScenario[] }>('/api/quiz');
      if (Array.isArray(data.scenarios)) {
        setScenarios(data.scenarios);
      } else {
        setLoadError(t.hero.networkError);
      }
    } catch {
      setLoadError(t.hero.networkError);
    } finally {
      setLoading(false);
    }
  }, [t.hero.networkError]);

  useEffect(() => {
    void loadQuiz();
  }, [loadQuiz]);

  const current = scenarios[currentIndex];

  const handleAnswer = async (userSaysScam: boolean) => {
    if (!current || submitting || feedback) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const result = await apiJson<QuizVerifyResult>('/api/quiz/verify', {
        id: current.id,
        is_scam: userSaysScam,
        lang,
      });
      setFeedback(result);
      if (result.correct) {
        const nextStreak = streak + 1;
        setCorrectCount((prev) => prev + 1);
        setStreak(nextStreak);
        const earned: BadgeId[] = ['first_catch'];
        if (nextStreak >= 3) earned.push('streak_three');
        unlockBadges(earned);
      } else {
        setStreak(0);
      }
    } catch (err) {
      setSubmitError(getApiErrorMessage(err, t.hero));
    } finally {
      setSubmitting(false);
    }
  };

  const handleNext = () => {
    setFeedback(null);
    setSubmitError(null);
    if (currentIndex + 1 >= scenarios.length) {
      setFinished(true);
      const total = scenarios.length;
      if (total > 0) {
        const ratio = correctCount / total;
        const earned: BadgeId[] = [];
        if (ratio >= 0.6) earned.push('cyber_defender');
        if (correctCount === total) earned.push('perfect_shield');
        unlockBadges(earned);
      }
    } else {
      setCurrentIndex((prev) => prev + 1);
    }
  };

  const handleRestart = () => {
    setCurrentIndex(0);
    setCorrectCount(0);
    setStreak(0);
    setFeedback(null);
    setSubmitError(null);
    setFinished(false);
  };

  return (
    <section
      id="quiz"
      aria-labelledby="quiz-heading"
      className="mt-16 scroll-mt-24 border-t border-black/10 pt-12 text-start"
    >
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2
            id="quiz-heading"
            className="text-2xl font-medium text-black"
            style={{ fontFamily: 'var(--font-heading)' }}
          >
            {t.quiz.title}
          </h2>
          <p className="mt-1.5 text-sm text-black/65">{t.quiz.subtitle}</p>
        </div>

        {scenarios.length > 0 ? (
          <div className="flex flex-wrap items-center gap-3 text-xs tabular-nums text-black/65">
            <span>
              {t.quiz.progressLabel}: {Math.min(currentIndex + 1, scenarios.length)} /{' '}
              {scenarios.length}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-medium text-black">
              {t.quiz.scoreLabel}: {correctCount} / {scenarios.length}
            </span>
            <span aria-hidden="true">·</span>
            <span>
              {t.quiz.streakLabel}: <strong className="text-black">{streak}</strong>
            </span>
          </div>
        ) : null}
      </div>

      <div className="mt-6 rounded-2xl border border-black/10 bg-white p-5 sm:p-6">
        {loading ? (
          <div className="h-36 animate-pulse rounded-xl bg-black/[0.04]" />
        ) : loadError ? (
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-[#dc2626]/20 bg-[#dc2626]/5 p-4">
            <p className="text-sm font-medium text-[#dc2626]" role="alert">
              {loadError}
            </p>
            <button
              type="button"
              onClick={() => void loadQuiz()}
              className="inline-flex min-h-9 items-center justify-center rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white"
            >
              {t.hero.retryButton}
            </button>
          </div>
        ) : finished ? (
          <div className="py-4 text-start" data-testid="quiz-completed">
            <h3 className="text-xl font-medium text-black">{t.quiz.completedTitle}</h3>
            <p className="mt-2 text-sm text-black/70">{t.quiz.completedBody}</p>
            <p className="mt-4 text-3xl font-medium tabular-nums text-black">
              {correctCount} / {scenarios.length}
            </p>
            <button
              type="button"
              onClick={handleRestart}
              className="mt-5 inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
            >
              {t.quiz.restartButton}
            </button>
          </div>
        ) : current ? (
          <div data-testid="quiz-card">
            <div className="flex flex-wrap items-center gap-2 text-xs text-black/55">
              <span>{current.channel}</span>
              <span aria-hidden="true">·</span>
              <span dir="ltr">{current.sender}</span>
            </div>

            <blockquote className="mt-3 rounded-xl border border-black/10 bg-[#f7f7f5] p-4 text-base leading-relaxed text-black">
              {lang === 'ar' ? current.text_ar : current.text_en}
            </blockquote>

            {!feedback ? (
              <div>
                <div className="mt-5 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={() => void handleAnswer(true)}
                    className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
                  >
                    {t.quiz.scamButton}
                  </button>
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={() => void handleAnswer(false)}
                    className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-6 py-2 text-sm font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
                  >
                    {t.quiz.safeButton}
                  </button>
                </div>
                {submitError ? (
                  <p className="mt-3 text-xs font-medium text-[#dc2626]" role="alert">
                    {submitError}
                  </p>
                ) : null}
              </div>
            ) : (
              <div
                className="kashf-result-enter mt-5 rounded-xl border border-black/10 bg-[#f7f7f5] p-4"
                data-testid="quiz-feedback"
              >
                <p
                  className={`text-sm font-medium ${
                    feedback.correct ? 'text-[#16a34a]' : 'text-[#dc2626]'
                  }`}
                >
                  {feedback.correct ? t.quiz.correctBadge : t.quiz.wrongBadge}
                </p>
                <p className="mt-2 text-sm leading-relaxed text-black/80">
                  {lang === 'ar' ? feedback.explanation_ar : feedback.explanation_en}
                </p>
                <p className="mt-2.5 text-xs tabular-nums text-black/60">
                  {t.quiz.pythonProofLabel} {t.result.verdicts[feedback.analysis.verdict]} (
                  {feedback.analysis.score}/100)
                </p>
                <button
                  type="button"
                  onClick={handleNext}
                  className="mt-4 inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full bg-black px-5 py-2 text-xs font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
                >
                  {t.quiz.nextButton}
                </button>
              </div>
            )}
          </div>
        ) : null}

        {/* Gamified Cyber Awareness Badges */}
        <div className="mt-6 border-t border-black/10 pt-5" data-testid="quiz-badges">
          <div className="flex items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-sm font-medium text-black">
              <Award className="h-4 w-4 text-black/70" aria-hidden="true" />
              <span>{t.quiz.badgesTitle}</span>
            </h3>
            <span className="text-xs tabular-nums text-black/55">
              {unlockedBadges.length} / {t.quiz.badges.length}
            </span>
          </div>

          <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
            {t.quiz.badges.map((badge) => {
              const unlocked = unlockedBadges.includes(badge.id);
              return (
                <div
                  key={badge.id}
                  data-unlocked={unlocked ? 'true' : 'false'}
                  className={`rounded-xl border px-3.5 py-3 text-start transition-colors ${
                    unlocked
                      ? 'border-black/25 bg-[#f7f7f5] text-black'
                      : 'border-black/10 bg-white text-black/45'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium">{badge.title}</span>
                    {unlocked ? (
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-[#16a34a]" aria-hidden="true" />
                    ) : null}
                  </div>
                  <p className="mt-1 text-[11px] leading-snug">{badge.requirement}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}

import { useEffect, useState } from 'react';
import type { Verdict } from '../types';

interface RiskGaugeProps {
  score: number;
  verdict: Verdict;
  scoreLabel: string;
  outOfHundred: string;
}

const VERDICT_STROKE: Record<Verdict, string> = {
  safe: '#16a34a',
  suspicious: '#d97706',
  dangerous: '#dc2626',
};

export function RiskGauge({
  score,
  verdict,
  scoreLabel,
  outOfHundred,
}: RiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const [displayScore, setDisplayScore] = useState(0);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced) {
      setDisplayScore(clamped);
      setProgress(clamped);
      return;
    }

    setDisplayScore(0);
    setProgress(0);

    let rafId = 0;
    const duration = 1000;
    const start = performance.now();

    const tick = (now: number) => {
      const elapsed = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - elapsed, 3);
      const current = eased * clamped;
      setProgress(current);
      setDisplayScore(Math.round(current));
      if (elapsed < 1) {
        rafId = requestAnimationFrame(tick);
      }
    };

    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [clamped]);

  const size = 168;
  const strokeWidth = 11;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - progress / 100);
  const strokeColor = VERDICT_STROKE[verdict];

  return (
    <div
      className="relative flex flex-col items-center justify-center"
      aria-label={`${scoreLabel}: ${clamped} ${outOfHundred}`}
    >
      <div className="relative h-[168px] w-[168px]">
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="-rotate-90"
          aria-hidden="true"
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(0, 0, 0, 0.08)"
            strokeWidth={strokeWidth}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span
            className="text-4xl font-medium leading-none tabular-nums text-black"
            data-testid="risk-score-value"
          >
            {displayScore}
          </span>
          <span className="mt-1 text-xs font-normal tabular-nums text-black/50">
            {outOfHundred}
          </span>
        </div>
      </div>
      <span className="mt-2 text-xs font-normal text-black/60">{scoreLabel}</span>
    </div>
  );
}

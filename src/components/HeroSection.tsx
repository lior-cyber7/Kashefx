import { useEffect, useState } from 'react';
import type { TranslationBundle } from '../i18n';
import { useTypewriter } from '../hooks/useTypewriter';

interface HeroSectionProps {
  t: TranslationBundle;
  onStartAnalyze: () => void;
  onSelectExample: (text: string) => void;
}

export function HeroSection({
  t,
  onStartAnalyze,
  onSelectExample,
}: HeroSectionProps) {
  const { displayed, done } = useTypewriter(t.hero.typewriterText, 38, 600);
  const [pillsVisible, setPillsVisible] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced) {
      setPillsVisible(true);
      return;
    }

    const timer = setTimeout(() => {
      setPillsVisible(true);
    }, 400);

    return () => clearTimeout(timer);
  }, []);

  const handleCopyEmail = async () => {
    try {
      await navigator.clipboard.writeText(t.hero.reachUsEmail);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  const whitePillClass =
    'inline-flex items-center justify-center bg-white text-black border border-black/10 rounded-full text-[13px] sm:text-[15px] px-4 sm:px-5 py-[0.3em] mx-[0.2em] mb-[0.4em] whitespace-nowrap hover:bg-black hover:text-white transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black';

  return (
    <section
      id="hero"
      className="relative z-[1] flex h-screen flex-col justify-end overflow-hidden px-5 pb-12 sm:px-8 md:justify-center md:px-10 md:pb-0"
    >
      <div className="relative z-10 max-w-md rounded-2xl bg-white/55 p-4 backdrop-blur-[2px] md:bg-transparent md:p-0 md:backdrop-blur-none text-start">
        {/* 1. Blurred intro label */}
        <p
          aria-hidden="true"
          className="pointer-events-none select-none mb-5 sm:mb-6"
          style={{
            fontSize: 'clamp(18px, 4vw, 26px)',
            lineHeight: 1.3,
            fontWeight: 400,
            color: '#000',
            filter: 'blur(4px)',
          }}
        >
          {t.hero.blurredLine1}
          <br />
          {t.hero.blurredLine2}
        </p>

        {/* 2. Typewriter text */}
        <p
          className="mb-5 text-black sm:mb-6"
          style={{
            fontSize: 'clamp(18px, 4vw, 26px)',
            lineHeight: 1.35,
            fontWeight: 400,
            minHeight: '54px',
          }}
        >
          <span>{displayed}</span>
          {!done ? (
            <span
              aria-hidden="true"
              className="cursor-blink ms-[2px] inline-block h-[1.1em] w-[2px] bg-black align-middle"
            />
          ) : null}
        </p>

        {/* 3. Action pill buttons (fade-in + slide-up 400ms after page load) */}
        <div
          className="flex flex-wrap gap-y-1"
          style={{
            opacity: pillsVisible ? 1 : 0,
            transform: pillsVisible ? 'translateY(0)' : 'translateY(8px)',
            transition: 'opacity 0.4s ease, transform 0.4s ease',
          }}
        >
          <button type="button" onClick={onStartAnalyze} className={whitePillClass}>
            {t.hero.analyzePill}
          </button>

          {t.hero.examples.map((ex) => (
            <button
              key={ex.id}
              type="button"
              onClick={() => onSelectExample(ex.text)}
              className={whitePillClass}
            >
              {ex.label}
            </button>
          ))}

          <button
            type="button"
            onClick={() => void handleCopyEmail()}
            className="mx-[0.2em] mb-[0.4em] inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full border border-white bg-black/20 px-4 py-[0.3em] text-[13px] text-white backdrop-blur-[2px] transition-colors duration-200 hover:bg-white hover:text-black focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white sm:gap-3 sm:px-5 sm:text-[15px]"
          >
            <span>
              {t.hero.reachUsPrefix}{' '}
              <span className="underline underline-offset-1">
                {copied ? t.hero.copiedLabel : t.hero.reachUsEmail}
              </span>
            </span>
            <svg
              width="12"
              height="12"
              viewBox="0 0 12 12"
              fill="none"
              aria-hidden="true"
              className="shrink-0"
            >
              <rect
                x="4"
                y="4"
                width="6.5"
                height="6.5"
                rx="1"
                stroke="currentColor"
                strokeWidth="1.2"
              />
              <path
                d="M8 4V2.5C8 1.94772 7.55228 1.5 7 1.5H2.5C1.94772 1.5 1.5 1.94772 1.5 2.5V7C1.5 7.55228 1.94772 8 2.5 8H4"
                stroke="currentColor"
                strokeWidth="1.2"
              />
            </svg>
          </button>
        </div>
      </div>
    </section>
  );
}

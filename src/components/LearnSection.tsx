import { useState } from 'react';
import type { TranslationBundle } from '../i18n';

interface LearnSectionProps {
  t: TranslationBundle;
}

export function LearnSection({ t }: LearnSectionProps) {
  const [openId, setOpenId] = useState<string | null>('phishing');

  const handleToggle = (id: string) => {
    setOpenId((prev) => (prev === id ? null : id));
  };

  return (
    <section
      id="learn"
      aria-labelledby="learn-heading"
      className="mt-16 scroll-mt-24 border-t border-black/10 pt-12 text-start"
    >
      <h2
        id="learn-heading"
        className="text-2xl font-medium text-black"
        style={{ fontFamily: 'var(--font-heading)' }}
      >
        {t.learn.title}
      </h2>
      <p className="mt-1.5 text-sm text-black/65">{t.learn.subtitle}</p>

      <div className="mt-6 divide-y divide-black/10 rounded-2xl border border-black/10 bg-white">
        {t.learn.items.map((item) => {
          const isOpen = openId === item.id;
          return (
            <div key={item.id}>
              <button
                type="button"
                onClick={() => handleToggle(item.id)}
                aria-expanded={isOpen}
                aria-controls={`learn-panel-${item.id}`}
                id={`learn-btn-${item.id}`}
                className="flex min-h-14 w-full items-center justify-between gap-4 px-5 py-4 text-start text-base font-medium text-black transition-opacity hover:opacity-70 focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-black sm:px-6"
              >
                <span>{item.question}</span>
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 18 18"
                  fill="none"
                  aria-hidden="true"
                  className={`shrink-0 transition-transform duration-200 ${
                    isOpen ? 'rotate-180' : ''
                  }`}
                >
                  <path
                    d="M4.5 6.75L9 11.25L13.5 6.75"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </button>

              {isOpen ? (
                <div
                  id={`learn-panel-${item.id}`}
                  role="region"
                  aria-labelledby={`learn-btn-${item.id}`}
                  className="px-5 pb-5 text-sm leading-relaxed text-black/75 sm:px-6"
                >
                  {item.answer}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}

import type { LocalHistoryItem, Verdict } from '../types';
import type { TranslationBundle } from '../i18n';

interface ScanHistoryProps {
  t: TranslationBundle;
  items: LocalHistoryItem[];
  onReopen: (text: string) => void;
  onClearAll: () => void;
}

const VERDICT_CLASS: Record<Verdict, string> = {
  safe: 'text-[#16a34a]',
  suspicious: 'text-[#d97706]',
  dangerous: 'text-[#dc2626]',
};

export function ScanHistory({ t, items, onReopen, onClearAll }: ScanHistoryProps) {
  return (
    <div className="mt-6 rounded-2xl border border-black/10 bg-white p-5 text-start sm:p-6" data-testid="scan-history">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium text-black">{t.history.title}</h2>
          <p className="mt-1 text-sm text-black/65">{t.history.subtitle}</p>
        </div>

        {items.length > 0 ? (
          <button
            type="button"
            onClick={onClearAll}
            className="inline-flex min-h-9 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
          >
            {t.history.clearAll}
          </button>
        ) : null}
      </div>

      {items.length === 0 ? (
        <div className="mt-6 rounded-xl border border-black/10 bg-[#f7f7f5] p-5">
          <h3 className="text-sm font-medium text-black">{t.history.emptyTitle}</h3>
          <p className="mt-1 text-xs leading-relaxed text-black/65">{t.history.emptyBody}</p>
        </div>
      ) : (
        <ul className="mt-5 divide-y divide-black/10">
          {items.map((entry) => (
            <li
              key={entry.id}
              className="flex flex-col justify-between gap-3 py-3.5 first:pt-0 last:pb-0 sm:flex-row sm:items-center"
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2 text-xs text-black/55">
                  <span className={`font-medium ${VERDICT_CLASS[entry.verdict]}`}>
                    {t.result.verdicts[entry.verdict]}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="tabular-nums">{entry.score}/100</span>
                  <span aria-hidden="true">·</span>
                  <span>{t.categories[entry.category] ?? t.categories.other}</span>
                </div>
                <p className="mt-1 truncate text-sm text-black">{entry.preview}</p>
              </div>
              <button
                type="button"
                onClick={() => onReopen(entry.text)}
                className="inline-flex min-h-9 shrink-0 items-center justify-center self-start whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black sm:self-center"
              >
                {t.history.reopenButton}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

import type { CommunityStats, TrendingItem } from '../types';
import type { TranslationBundle } from '../i18n';

interface TrendingSectionProps {
  t: TranslationBundle;
  items: TrendingItem[];
  stats: CommunityStats | null;
  loading: boolean;
  error: boolean;
  onRefresh: () => void;
}

export function TrendingSection({
  t,
  items,
  stats,
  loading,
  error,
  onRefresh,
}: TrendingSectionProps) {
  return (
    <section
      id="trending"
      aria-labelledby="trending-heading"
      className="mt-16 scroll-mt-24 border-t border-black/10 pt-12 text-start"
    >
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2
            id="trending-heading"
            className="text-2xl font-medium text-black"
            style={{ fontFamily: 'var(--font-heading)' }}
          >
            {t.trending.title}
          </h2>
          <p className="mt-1.5 text-sm text-black/65">{t.trending.subtitle}</p>
        </div>

        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-50"
        >
          {t.trending.retryButton}
        </button>
      </div>

      {stats && stats.total_reports > 0 ? (
        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-black/10 bg-white px-4 py-3.5">
            <span className="block text-xs text-black/55">{t.trending.totalReportsStat}</span>
            <span className="mt-1 block text-2xl font-medium tabular-nums text-black">
              {stats.total_reports}
            </span>
          </div>
          <div className="rounded-xl border border-black/10 bg-white px-4 py-3.5">
            <span className="block text-xs text-black/55">{t.trending.avgRiskStat}</span>
            <span className="mt-1 block text-2xl font-medium tabular-nums text-black">
              {stats.avg_score}/100
            </span>
          </div>
          <div className="rounded-xl border border-black/10 bg-white px-4 py-3.5">
            <span className="block text-xs text-black/55">{t.trending.topCategoryStat}</span>
            <span className="mt-1 block truncate text-base font-medium text-black">
              {stats.top_category ? (t.categories[stats.top_category] ?? t.categories.other) : '—'}
            </span>
          </div>
        </div>
      ) : null}

      {error ? (
        <div className="mt-6 rounded-2xl border border-black/10 bg-white p-6 text-sm text-black/75">
          {t.trending.errorText}
        </div>
      ) : loading && items.length === 0 ? (
        <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[0, 1, 2].map((idx) => (
            <div
              key={idx}
              className="h-36 rounded-2xl border border-black/10 bg-white p-5"
            >
              <div className="h-4 w-1/2 rounded bg-black/[0.06]" />
              <div className="mt-4 h-7 w-1/3 rounded bg-black/[0.06]" />
              <div className="mt-6 h-8 w-full rounded bg-black/[0.04]" />
            </div>
          ))}
        </div>
      ) : items.length === 0 ? (
        <div
          data-testid="trending-empty"
          className="mt-6 flex flex-col items-start gap-2 rounded-2xl border border-black/10 bg-white p-6 sm:p-8"
        >
          <h3 className="text-base font-medium text-black">{t.trending.emptyTitle}</h3>
          <p className="max-w-2xl text-sm leading-relaxed text-black/65">
            {t.trending.emptyBody}
          </p>
        </div>
      ) : (
        <div
          data-testid="trending-grid"
          className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3"
        >
          {items.map((item) => {
            const maxDay = Math.max(1, ...item.daily);
            const categoryTitle = t.categories[item.category] ?? t.categories.other;

            return (
              <article
                key={item.category}
                className="flex flex-col justify-between rounded-2xl border border-black/10 bg-white p-5"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 text-xs text-black/55">
                    <span>{t.trending.last7Days}</span>
                    <span className="tabular-nums">
                      {t.trending.avgScoreLabel}: {item.avg_score}/100
                    </span>
                  </div>
                  <h3 className="mt-2 text-base font-medium text-black">
                    {categoryTitle}
                  </h3>
                </div>

                <div className="mt-5 flex items-end justify-between gap-4">
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-3xl font-medium tabular-nums text-black">
                      {item.count}
                    </span>
                    <span className="text-xs text-black/55">
                      {t.trending.reportsUnit}
                    </span>
                  </div>

                  {/* Plain-div 7-day sparkline */}
                  <div className="flex h-10 items-end gap-1.5" aria-hidden="true">
                    {item.daily.map((val, dayIdx) => {
                      const heightPct =
                        val > 0 ? Math.max(18, Math.round((val / maxDay) * 100)) : 12;
                      return (
                        <div
                          key={dayIdx}
                          className={`w-2 rounded-sm ${
                            val > 0 ? 'bg-black' : 'bg-black/10'
                          }`}
                          style={{ height: `${heightPct}%` }}
                          title={`${val}`}
                        />
                      );
                    })}
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

import type { TranslationBundle } from '../i18n';

interface FooterProps {
  t: TranslationBundle;
}

export function Footer({ t }: FooterProps) {
  return (
    <footer className="mt-16 border-t border-black/10 py-8">
      <div className="mx-auto flex max-w-5xl flex-col items-start justify-between gap-3 px-5 text-xs text-black/60 sm:flex-row sm:items-center sm:px-8">
        <p>{t.footer.disclaimer}</p>
        <p>{t.footer.privacyReminder}</p>
      </div>
    </footer>
  );
}

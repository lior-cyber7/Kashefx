import { useEffect, useState } from 'react';
import type { Language } from '../types';
import type { TranslationBundle } from '../i18n';

interface NavbarProps {
  lang: Language;
  t: TranslationBundle;
  onToggleLang: () => void;
}

export function Navbar({ lang, t, onToggleLang }: NavbarProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      setScrolled(window.scrollY > 40);
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const navItems = [
    { href: '#analyzer', label: t.nav.analyzer },
    { href: '#trending', label: t.nav.trending },
    { href: '#quiz', label: t.nav.quiz },
    { href: '#learn', label: t.nav.learn },
  ];

  const comma = lang === 'ar' ? '، ' : ', ';

  const handleClose = () => setMenuOpen(false);

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-10 flex w-full items-center justify-between px-5 py-4 transition-colors duration-200 sm:px-8 sm:py-5 ${
          scrolled && !menuOpen
            ? 'border-b border-black/10 bg-white/90 backdrop-blur-md'
            : 'bg-transparent'
        }`}
      >
        {/* Logo (start) */}
        <a
          href="#hero"
          onClick={handleClose}
          className="flex shrink-0 items-center gap-3 whitespace-nowrap text-black focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-black"
        >
          <span
            className="text-[21px] tracking-tight text-black sm:text-[26px]"
            style={{ fontFamily: 'var(--font-heading)' }}
          >
            {lang === 'ar' ? `${t.brandAr}®` : `${t.brandEn}®`}
          </span>
          <span
            aria-hidden="true"
            className="select-none text-[25px] text-black sm:text-[30px]"
            style={{ letterSpacing: '-0.02em' }}
          >
            ✳︎
          </span>
        </a>

        {/* Desktop nav links (center, hidden below md) */}
        <nav
          aria-label={lang === 'ar' ? 'التنقل الرئيسي' : 'Primary navigation'}
          className="hidden items-center gap-2 text-[22px] text-black md:flex"
        >
          {navItems.map((item, idx) => (
            <span key={item.href} className="inline-flex items-center whitespace-nowrap">
              <a
                href={item.href}
                className="transition-opacity hover:opacity-60 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-black"
              >
                {item.label}
              </a>
              {idx < navItems.length - 1 ? <span aria-hidden="true">{comma.trim()}</span> : null}
            </span>
          ))}
        </nav>

        {/* Desktop CTA (end, hidden below md) */}
        <button
          type="button"
          onClick={onToggleLang}
          aria-label={t.nav.langToggleAria}
          className="hidden whitespace-nowrap text-[23px] text-black underline underline-offset-2 transition-opacity hover:opacity-60 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-black md:inline-block"
        >
          {t.nav.langToggle}
        </button>

        {/* Mobile hamburger (visible below md) */}
        <button
          type="button"
          onClick={() => setMenuOpen((prev) => !prev)}
          aria-expanded={menuOpen}
          aria-label={menuOpen ? t.nav.menuCloseAria : t.nav.menuOpenAria}
          className="relative z-20 flex h-10 w-10 flex-col items-center justify-center gap-[5px] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black md:hidden"
        >
          <span
            className={`block h-[2px] w-6 bg-black transition-all duration-300 ${
              menuOpen ? 'translate-y-[7px] rotate-45' : ''
            }`}
          />
          <span
            className={`block h-[2px] w-6 bg-black transition-all duration-300 ${
              menuOpen ? 'opacity-0' : 'opacity-100'
            }`}
          />
          <span
            className={`block h-[2px] w-6 bg-black transition-all duration-300 ${
              menuOpen ? '-translate-y-[7px] -rotate-45' : ''
            }`}
          />
        </button>
      </header>

      {/* Mobile overlay (z-index: 9) */}
      <div
        aria-hidden={!menuOpen}
        className={`fixed inset-0 z-[9] flex flex-col justify-center gap-8 bg-white/95 px-8 backdrop-blur-sm transition-opacity duration-300 md:hidden ${
          menuOpen ? 'pointer-events-auto opacity-100' : 'pointer-events-none opacity-0'
        }`}
      >
        <nav className="flex flex-col items-start gap-6">
          {navItems.map((item) => (
            <a
              key={item.href}
              href={item.href}
              onClick={handleClose}
              tabIndex={menuOpen ? 0 : -1}
              className="text-[32px] font-medium text-black transition-opacity hover:opacity-60 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-black"
            >
              {item.label}
            </a>
          ))}
        </nav>

        <button
          type="button"
          onClick={() => {
            onToggleLang();
            handleClose();
          }}
          tabIndex={menuOpen ? 0 : -1}
          aria-label={t.nav.langToggleAria}
          className="self-start text-[32px] font-medium text-black underline underline-offset-4 transition-opacity hover:opacity-60 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-black"
        >
          {t.nav.langToggle}
        </button>
      </div>
    </>
  );
}

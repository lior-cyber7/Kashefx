import { useState } from 'react';
import type {
  Language,
  LiveUrlProbeResult,
  ThreatSourceStatus,
  UrlClassification,
  UrlForensics,
} from '../types';
import type { TranslationBundle } from '../i18n';
import { apiJson, getApiErrorMessage } from '../utils/api';
import { EvidenceBundlePanel } from './EvidenceBundlePanel';

interface UrlForensicsPanelProps {
  forensics: UrlForensics;
  lang: Language;
  t: TranslationBundle;
  initialProbe?: LiveUrlProbeResult | null;
  onOpenSandbox?: (url: string) => void;
}

const CLASSIFICATION_TEXT_CLASS: Record<UrlClassification, string> = {
  malicious: 'text-[#dc2626]',
  suspicious: 'text-[#d97706]',
  no_known_threat: 'text-[#16a34a]',
  unknown: 'text-black/75',
};

const TI_STATUS_TEXT_CLASS: Record<ThreatSourceStatus, string> = {
  hit: 'text-[#dc2626] font-medium',
  clean: 'text-[#16a34a]',
  not_configured: 'text-black/55',
  unavailable: 'text-[#d97706]',
  error: 'text-[#d97706]',
};

export function UrlForensicsPanel({
  forensics,
  lang,
  t,
  initialProbe = null,
  onOpenSandbox,
}: UrlForensicsPanelProps) {
  const isAr = lang === 'ar';
  const [copiedDefang, setCopiedDefang] = useState(false);
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<LiveUrlProbeResult | null>(initialProbe);
  const [probeError, setProbeError] = useState<string | null>(null);

  const effectiveClassification: UrlClassification =
    probeResult?.classification ?? forensics.classification ?? 'unknown';
  const activeBundle = probeResult?.evidence_bundle ?? forensics.evidence_bundle;

  const handleCopyDefanged = async () => {
    try {
      await navigator.clipboard.writeText(forensics.defanged_url);
      setCopiedDefang(true);
      setTimeout(() => setCopiedDefang(false), 1800);
    } catch {
      setCopiedDefang(false);
    }
  };

  const handleLiveProbe = async () => {
    if (probing) return;
    setProbing(true);
    setProbeError(null);
    try {
      const data = await apiJson<LiveUrlProbeResult>('/api/inspect-url', {
        url: forensics.original_url,
        include_intel: true,
      });
      setProbeResult(data);
    } catch (err) {
      setProbeError(getApiErrorMessage(err, t.hero));
    } finally {
      setProbing(false);
    }
  };

  return (
    <div
      className="space-y-4 rounded-xl border border-black/10 bg-[#f7f7f5] p-4 text-start"
      data-testid="url-forensics-panel"
    >
      {/* 1. Overall 4-State Verdict Header */}
      <div className="flex flex-wrap items-start justify-between gap-2 border-b border-black/10 pb-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-xs text-black/60">
            <span className={`text-sm font-medium ${CLASSIFICATION_TEXT_CLASS[effectiveClassification]}`} data-testid="url-classification-label">
              {t.result.urlClassifications[effectiveClassification]}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">
              {t.result.entropyLabel}: {forensics.entropy}
            </span>
            {forensics.tld ? (
              <>
                <span aria-hidden="true">·</span>
                <span dir="ltr" className="font-mono">
                  {forensics.tld}
                </span>
              </>
            ) : null}
          </div>
          <p className="mt-1 text-start font-mono text-xs font-medium text-black break-all">
            <span dir="ltr">{forensics.host || forensics.original_url}</span>
          </p>
        </div>

        {probeResult?.scan_timestamp ? (
          <time
            dateTime={probeResult.scan_timestamp}
            className="font-mono text-[11px] tabular-nums text-black/50"
            dir="ltr"
          >
            {probeResult.scan_timestamp}
          </time>
        ) : null}
      </div>

      {effectiveClassification === 'no_known_threat' ? (
        <p className="text-xs leading-relaxed text-black/70">
          {t.result.noKnownThreatNote}
        </p>
      ) : null}

      {forensics.is_mixed_script_homograph ? (
        <p className="text-xs font-medium text-[#dc2626]">
          {isAr
            ? `تحذير هجوم أحرف متشابهة (Homograph): ${forensics.homograph_skeleton}`
            : `Mixed-script Homograph spoofing skeleton: ${forensics.homograph_skeleton}`}
        </p>
      ) : null}

      {forensics.has_punycode && forensics.punycode_decoded_host !== forensics.host ? (
        <p className="text-xs text-[#dc2626]">
          Punycode → <span className="font-mono" dir="ltr">{forensics.punycode_decoded_host}</span>
        </p>
      ) : null}

      {forensics.matched_brand ? (
        <p
          className={`text-xs font-medium ${
            forensics.is_official_brand ? 'text-[#16a34a]' : 'text-[#dc2626]'
          }`}
        >
          {forensics.is_official_brand
            ? `${t.result.officialDomainLabel}: ${forensics.matched_brand}`
            : `${t.result.impersonationLabel}: ${forensics.matched_brand}`}
        </p>
      ) : null}

      {/* Safe Defanged Copy */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-black/10 bg-white px-3 py-2">
        <div className="min-w-0 flex-1">
          <span className="block text-[11px] text-black/55">{t.result.defangedLabel}</span>
          <code className="block truncate font-mono text-xs text-black" dir="ltr">
            {forensics.defanged_url}
          </code>
        </div>
        <button
          type="button"
          onClick={() => void handleCopyDefanged()}
          className="inline-flex min-h-8 shrink-0 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
        >
          {copiedDefang ? t.result.copiedDefanged : t.result.copyDefanged}
        </button>
      </div>

      {/* Static Flags fallback when evidence bundle absent */}
      {!activeBundle?.evidence?.length && forensics.flags.length > 0 ? (
        <ul className="space-y-1">
          {forensics.flags.map((flag, i) => (
            <li
              key={i}
              className={`text-xs ${
                flag.severity === 'safe'
                  ? 'text-[#16a34a]'
                  : flag.severity === 'high'
                    ? 'text-[#dc2626]'
                    : 'text-[#d97706]'
              }`}
            >
              · {isAr ? flag.title_ar : flag.title_en}
            </li>
          ))}
        </ul>
      ) : null}

      {/* Action Buttons if not yet live-probed */}
      {!probeResult ? (
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void handleLiveProbe()}
              disabled={probing}
              data-testid="live-probe-btn"
              className="inline-flex min-h-9 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
            >
              {probing ? t.result.liveProbingButton : t.result.liveProbeButton}
            </button>

            {onOpenSandbox ? (
              <button
                type="button"
                onClick={() => onOpenSandbox(forensics.original_url)}
                data-testid="open-in-sandbox-btn"
                className="inline-flex min-h-9 items-center justify-center whitespace-nowrap rounded-full bg-black px-4 py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
              >
                {t.result.openSandboxButton}
              </button>
            ) : null}
          </div>
          {probeError ? (
            <p className="mt-2 text-xs text-[#dc2626]" role="alert">
              {probeError}
            </p>
          ) : null}
        </div>
      ) : (
        <div className="space-y-4">
          {/* 2. Threat Intelligence Sources (Separate Status + Timestamp) */}
          {probeResult.threat_intel && probeResult.threat_intel.length > 0 ? (
            <div
              className="rounded-xl border border-black/10 bg-white p-3.5"
              data-testid="threat-intel-sources"
            >
              <h4 className="text-xs font-medium text-black">{t.result.threatIntelTitle}</h4>
              <ul className="mt-2.5 divide-y divide-black/10 text-xs">
                {probeResult.threat_intel.map((src) => (
                  <li key={src.source_id} className="py-2 first:pt-0 last:pb-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium text-black">{src.source_name}</span>
                      <div className="flex items-center gap-2">
                        {src.detection_ratio ? (
                          <span className="font-mono tabular-nums text-black" dir="ltr">
                            {src.detection_ratio}
                          </span>
                        ) : null}
                        <span className={TI_STATUS_TEXT_CLASS[src.status]}>
                          {t.result.threatStatusLabels[src.status]}
                        </span>
                      </div>
                    </div>
                    <div className="mt-1 flex flex-wrap items-baseline justify-between gap-2 text-[11px] text-black/65">
                      <span>{isAr ? src.verdict_detail_ar : src.verdict_detail_en}</span>
                      <time dateTime={src.checked_at} className="font-mono tabular-nums text-black/45" dir="ltr">
                        {src.checked_at}
                      </time>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {/* 3. Expandable Technical Analysis (DNS, RDAP, TLS, Redirects, Scripts, Query Params) */}
          <details
            open
            className="rounded-xl border border-black/10 bg-white p-3.5 text-xs"
            data-testid="technical-details-accordion"
          >
            <summary className="cursor-pointer font-medium text-black select-none">
              {t.result.technicalDetailsTitle}
            </summary>

            <div className="mt-3 space-y-2.5 border-t border-black/10 pt-3">
              {/* RDAP Domain Age */}
              {probeResult.rdap ? (
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-black">{t.result.rdapLabel}</span>
                  <span className="font-mono tabular-nums text-black/75" dir="ltr">
                    {probeResult.rdap.available && probeResult.rdap.age_days !== null
                      ? `${probeResult.rdap.age_days} days (${probeResult.rdap.registered_at ?? ''})`
                      : probeResult.rdap.error || 'Unavailable'}
                  </span>
                </div>
              ) : null}

              {/* DNS / IP */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-black/10 pt-2">
                <span className="font-medium text-black">{t.result.dnsLabel}</span>
                <span className="font-mono text-black/75" dir="ltr">
                  {probeResult.dns.resolved
                    ? probeResult.dns.ips.join(', ')
                    : probeResult.dns.error || 'Unresolved'}
                </span>
              </div>

              {/* Extended DNS (A / MX / TXT / SPF) */}
              {probeResult.dns_records?.available ? (
                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-black/10 pt-2">
                  <span className="font-medium text-black">{t.result.dnsRecordsLabel}</span>
                  <span className="font-mono text-black/75" dir="ltr">
                    A:{probeResult.dns_records.a.length} · MX:{probeResult.dns_records.mx.length} · SPF:{probeResult.dns_records.has_spf ? 'Yes' : 'No'}
                  </span>
                </div>
              ) : null}

              {/* TLS */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-black/10 pt-2">
                <span className="font-medium text-black">{t.result.tlsLabel}</span>
                <span className={probeResult.tls.valid ? 'text-[#16a34a]' : 'text-[#d97706]'}>
                  {probeResult.tls.available && probeResult.tls.valid
                    ? `${probeResult.tls.issuer ?? 'TLS'} (${
                        probeResult.tls.days_remaining != null
                          ? `${probeResult.tls.days_remaining}d`
                          : 'valid'
                      })`
                    : probeResult.tls.error || 'No HTTPS'}
                </span>
              </div>

              {/* Unicode Scripts */}
              {forensics.scripts_detected && forensics.scripts_detected.length > 0 ? (
                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-black/10 pt-2">
                  <span className="font-medium text-black">{t.result.scriptsLabel}</span>
                  <span className="font-mono text-black/75" dir="ltr">
                    {forensics.scripts_detected.join(', ')}
                  </span>
                </div>
              ) : null}

              {/* Sanitized URL */}
              {forensics.tracking_params_removed.length > 0 ? (
                <div className="border-t border-black/10 pt-2">
                  <span className="block font-medium text-black">
                    {t.result.sanitizedLabel} ({forensics.tracking_params_removed.join(', ')})
                  </span>
                  <code className="mt-1 block truncate font-mono text-[11px] text-black/75" dir="ltr">
                    {forensics.sanitized_url}
                  </code>
                </div>
              ) : null}

              {/* Redirects */}
              {probeResult.redirects.length > 0 ? (
                <div className="border-t border-black/10 pt-2">
                  <span className="font-medium text-black">{t.result.redirectsLabel}</span>
                  <ol className="mt-1 space-y-1 font-mono text-[11px] text-black/75" dir="ltr">
                    {probeResult.redirects.map((hop, idx) => (
                      <li key={idx} className="truncate">
                        [{hop.status}] {hop.url}
                      </li>
                    ))}
                  </ol>
                  {probeResult.final_url !== forensics.normalized_url ? (
                    <p className="mt-1.5 text-xs text-black">
                      <span className="font-medium">{t.result.finalUrlLabel}: </span>
                      <span className="font-mono break-all" dir="ltr">
                        {probeResult.final_url}
                      </span>
                    </p>
                  ) : null}
                </div>
              ) : null}
            </div>
          </details>

          {/* 4. Recommended Actions */}
          {probeResult.recommended_actions && probeResult.recommended_actions.length > 0 ? (
            <div className="rounded-xl border border-black/10 bg-white p-3.5 text-xs">
              <h4 className="font-medium text-black">{t.result.whatToDoTitle}</h4>
              <ul className="mt-2 space-y-1 text-black/75">
                {probeResult.recommended_actions.map((act, idx) => (
                  <li key={idx}>· {isAr ? act.ar : act.en}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {onOpenSandbox ? (
            <div>
              <button
                type="button"
                onClick={() => onOpenSandbox(forensics.original_url)}
                data-testid="open-in-sandbox-btn"
                className="inline-flex min-h-9 items-center justify-center whitespace-nowrap rounded-full bg-black px-4 py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-85 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
              >
                {t.result.openSandboxButton}
              </button>
            </div>
          ) : null}
        </div>
      )}

      {/* 5. Evidence Bundle (Confidence, Conflicts, Limitations, Scan Timestamp) */}
      {activeBundle ? (
        <div className="rounded-xl border border-black/10 bg-white p-3.5">
          <EvidenceBundlePanel bundle={activeBundle} lang={lang} />
        </div>
      ) : null}
    </div>
  );
}

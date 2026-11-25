export type Language = 'ar' | 'en';
export type Verdict = 'safe' | 'suspicious' | 'dangerous';
export type ScamCategory =
  | 'phishing_bank'
  | 'fake_prize'
  | 'fake_delivery'
  | 'investment_fraud'
  | 'otp_theft'
  | 'fake_job'
  | 'other';

export type UrlClassification = 'malicious' | 'suspicious' | 'no_known_threat' | 'unknown';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal';
export type EvidenceStrength = 'strong' | 'moderate' | 'weak' | 'insufficient';
export type ThreatSourceStatus = 'hit' | 'clean' | 'not_configured' | 'unavailable' | 'error';

export interface AnalysisReason {
  id: string;
  points: number;
  title_ar: string;
  title_en: string;
  detail_ar: string;
  detail_en: string;
  match: string;
}

export interface EvidenceItem {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe';
  title_ar: string;
  title_en: string;
  detail_ar: string;
  detail_en: string;
  source: string;
  timestamp: string;
  observed_value: string;
}

export interface SourceConflict {
  topic_ar: string;
  topic_en: string;
  source_a: string;
  result_a: string;
  source_b: string;
  result_b: string;
}

export interface EvidenceBundle {
  scan_timestamp: string;
  risk_level: RiskLevel;
  evidence: EvidenceItem[];
  conflicts: SourceConflict[];
  limitations: Array<{ code: string; ar: string; en: string }>;
  confidence: {
    calibrated: boolean;
    evidence_strength: EvidenceStrength;
    calibrated_probability: number | null;
    detection_ratio: string | null;
    explanation_ar: string;
    explanation_en: string;
  };
}

export interface ThreatSourceResult {
  source_id: string;
  source_name: string;
  status: ThreatSourceStatus;
  verdict_detail_ar: string;
  verdict_detail_en: string;
  checked_at: string;
  detection_ratio: string | null;
}

export interface UrlForensicFlag {
  severity: 'high' | 'medium' | 'low' | 'safe';
  title_ar: string;
  title_en: string;
}

export interface UrlForensics {
  original_url: string;
  normalized_url: string;
  defanged_url: string;
  sanitized_url: string;
  host: string;
  punycode_decoded_host: string;
  tld: string;
  entropy: number;
  is_shortener: boolean;
  has_punycode: boolean;
  is_mixed_script_homograph?: boolean;
  scripts_detected?: string[];
  homograph_skeleton?: string;
  tracking_params_removed: string[];
  matched_brand: string | null;
  is_official_brand: boolean;
  forensic_score: number;
  classification?: UrlClassification;
  verdict: Verdict;
  flags: UrlForensicFlag[];
  evidence_bundle?: EvidenceBundle;
}

export interface LiveUrlProbeResult {
  forensics: UrlForensics;
  dns: { resolved: boolean; ips: string[]; error: string | null };
  dns_records?: { available: boolean; a: string[]; mx: string[]; has_spf: boolean };
  rdap?: { available: boolean; age_days: number | null; registered_at?: string | null; error?: string | null };
  tls: { available: boolean; valid: boolean; issuer?: string; days_remaining?: number | null; error?: string };
  redirects: Array<{ url: string; status: number }>;
  final_url: string;
  threat_intel?: ThreatSourceResult[];
  classification?: UrlClassification;
  evidence_bundle?: EvidenceBundle;
  recommended_actions?: Array<{ ar: string; en: string }>;
  scan_timestamp?: string;
}

export interface GroupedSuspiciousSegment {
  text: string;
  severity: string;
  labels_ar: string[];
  labels_en: string[];
  reasons_ar: string[];
  reasons_en: string[];
}

export interface LinkVerificationItem {
  url: string;
  defanged_url: string;
  reason_ar: string;
  reason_en: string;
}

export interface AnalysisResult {
  score: number;
  verdict: Verdict;
  category: ScamCategory;
  reasons: AnalysisReason[];
  highlight_segments?: Array<{ text: string; highlighted: boolean }>;
  grouped_suspicious_segments?: GroupedSuspiciousSegment[];
  links_requiring_verification?: LinkVerificationItem[];
  recommended_actions?: Array<{ ar: string; en: string }>;
  family_warning?: { ar: string; en: string };
  fingerprint: string;
  url_forensics?: UrlForensics[];
  evidence_bundle?: EvidenceBundle;
}

export interface BatchAnalysisResult {
  total: number;
  dangerous_count: number;
  suspicious_count: number;
  safe_count: number;
  items: Array<{ index: number; preview: string; text: string; result: AnalysisResult }>;
}

export interface QuizScenario {
  id: string;
  channel: string;
  sender: string;
  text_ar: string;
  text_en: string;
}

export interface QuizVerifyResult {
  id: string;
  correct: boolean;
  is_scam: boolean;
  explanation_ar: string;
  explanation_en: string;
  analysis: AnalysisResult;
}

export interface TrendingItem {
  category: ScamCategory;
  count: number;
  avg_score: number;
  daily: number[];
}

export interface CommunityStats {
  total_reports: number;
  avg_score: number;
  top_category: ScamCategory | null;
}

export interface LocalHistoryItem {
  id: string;
  timestamp: number;
  preview: string;
  text: string;
  score: number;
  verdict: Verdict;
  category: ScamCategory;
}

export type AcademicVerdict = 'authentic' | 'review_needed' | 'flagged';
export type BehaviorStatus = 'not_captured' | 'human_verified' | 'robotic_cadence' | 'bulk_pasted' | 'mixed_input';

export interface BehaviorTelemetry {
  keystrokes: number;
  pasted_chars: number;
  total_chars: number;
  avg_interval_ms: number;
  interval_std_ms: number;
}

export interface AcademicAnalysisResult {
  word_count: number;
  sentence_count: number;
  lexical_richness: number;
  burstiness: number;
  ai_probability: number | null;
  plagiarism_pct: number;
  originality_score: number;
  verdict: AcademicVerdict;
  plagiarism_matches: Array<{ source: string; overlap_pct: number; sample: string }>;
  behavior: { status: BehaviorStatus; score: number; paste_ratio: number };
  signals: Array<{ severity: 'high' | 'medium' | 'low' | 'safe'; title_ar: string; title_en: string; detail: string }>;
  ai_detection?: {
    language: 'ar' | 'en';
    classification: 'human_leaning' | 'ai_leaning' | 'inconclusive';
    headline_ar: string;
    headline_en: string;
    model_oof_brier: number;
    metrics: { perplexity_proxy: number; root_ttr: number; hapax_ratio: number; punctuation_entropy: number };
    evidence_bundle: EvidenceBundle;
  };
  eligible_for_certificate: boolean;
}

export interface DlpScanResult {
  risk_score: number;
  verdict: Verdict;
  dlp_findings: Array<{ id: string; title_ar: string; title_en: string; masked_value: string; severity: 'high' | 'medium' }>;
  url_forensics: UrlForensics[];
}

export interface CertificateRecord {
  block_index: number;
  cert_id: string;
  originality_score: number;
  doc_hash: string;
  block_hash: string;
}

export interface UrlSandboxResult {
  defanged_url: string;
  execution_mode: 'live_captured' | 'simulated_offline' | 'blocked_ssrf' | 'blocked_unsafe_scheme';
  sandbox_score: number;
  verdict: Verdict;
  network_trace: {
    redirects: Array<{ url: string; status: number }>;
    final_url: string;
    http_status: number | null;
    content_type: string | null;
    cookies_attempted: number;
  };
  dom_telemetry: {
    page_title: string;
    visible_text_preview: string;
    forms_count: number;
    password_inputs: number;
    sensitive_inputs: string[];
    scripts_count: number;
    obfuscated_js_hits: number;
    hidden_iframes_count: number;
  };
  what_it_tries_to_do: Array<{
    id: string;
    severity: 'high' | 'medium' | 'low' | 'safe';
    observed: boolean;
    title_ar: string;
    title_en: string;
    detail_ar: string;
    detail_en: string;
  }>;
}

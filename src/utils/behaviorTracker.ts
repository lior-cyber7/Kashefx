import type { BehaviorTelemetry } from '../types';

export interface BehaviorCaptureState {
  intervalsMs: number[];
  keystrokes: number;
  pastedChars: number;
  totalChars: number;
}

export function computeIntervalStats(intervalsMs: number[]): {
  avg_interval_ms: number;
  interval_std_ms: number;
} {
  const valid = intervalsMs.filter(
    (ms) => Number.isFinite(ms) && ms >= 10 && ms <= 2500
  );
  if (valid.length === 0) {
    return { avg_interval_ms: 0, interval_std_ms: 0 };
  }
  const mean = valid.reduce((sum, val) => sum + val, 0) / valid.length;
  const variance =
    valid.reduce((sum, val) => sum + (val - mean) ** 2, 0) / valid.length;
  return {
    avg_interval_ms: Math.round(mean * 10) / 10,
    interval_std_ms: Math.round(Math.sqrt(variance) * 10) / 10,
  };
}

export function buildBehaviorTelemetry(
  state: BehaviorCaptureState
): BehaviorTelemetry {
  const stats = computeIntervalStats(state.intervalsMs);
  return {
    keystrokes: Math.max(0, Math.round(state.keystrokes)),
    pasted_chars: Math.max(0, Math.round(state.pastedChars)),
    total_chars: Math.max(0, Math.round(state.totalChars)),
    avg_interval_ms: stats.avg_interval_ms,
    interval_std_ms: stats.interval_std_ms,
  };
}

export type LiveBehaviorPreview = 'not_captured' | 'human_cadence' | 'paste_heavy';

export function classifyBehaviorPreview(
  telemetry: BehaviorTelemetry
): LiveBehaviorPreview {
  if (telemetry.keystrokes === 0 && telemetry.pasted_chars === 0) {
    return 'not_captured';
  }
  const denom = Math.max(1, telemetry.total_chars);
  const pasteRatio = telemetry.pasted_chars / denom;
  if (pasteRatio >= 0.65) {
    return 'paste_heavy';
  }
  if (telemetry.keystrokes >= 10 && telemetry.interval_std_ms >= 20) {
    return 'human_cadence';
  }
  return telemetry.pasted_chars > telemetry.keystrokes * 2
    ? 'paste_heavy'
    : 'not_captured';
}

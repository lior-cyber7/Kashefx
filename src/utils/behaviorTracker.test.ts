import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildBehaviorTelemetry,
  classifyBehaviorPreview,
  computeIntervalStats,
} from './behaviorTracker.ts';

describe('computeIntervalStats', () => {
  it('returns zeros when no valid intervals exist', () => {
    assert.deepEqual(computeIntervalStats([]), {
      avg_interval_ms: 0,
      interval_std_ms: 0,
    });
    assert.deepEqual(computeIntervalStats([2, 5000]), {
      avg_interval_ms: 0,
      interval_std_ms: 0,
    });
  });

  it('computes mean and standard deviation filtering reading pauses', () => {
    const res = computeIntervalStats([100, 140, 220, 180, 9500]);
    assert.equal(res.avg_interval_ms, 160);
    assert.ok(res.interval_std_ms > 40 && res.interval_std_ms < 50);
  });
});

describe('buildBehaviorTelemetry & classifyBehaviorPreview', () => {
  it('detects organic human cadence when variance and keystrokes are high', () => {
    const telemetry = buildBehaviorTelemetry({
      intervalsMs: [95, 160, 210, 120, 280, 145, 190, 110, 240, 130, 175, 155],
      keystrokes: 25,
      pastedChars: 0,
      totalChars: 24,
    });
    assert.equal(telemetry.keystrokes, 25);
    assert.equal(classifyBehaviorPreview(telemetry), 'human_cadence');
  });

  it('flags bulk-pasted input when paste ratio dominates', () => {
    const telemetry = buildBehaviorTelemetry({
      intervalsMs: [120, 130],
      keystrokes: 2,
      pastedChars: 350,
      totalChars: 352,
    });
    assert.equal(classifyBehaviorPreview(telemetry), 'paste_heavy');
  });
});

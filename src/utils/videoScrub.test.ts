import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_RENDER_HEIGHT,
  MAX_RENDER_WIDTH,
  TOTAL_ROBOT_FRAMES,
  clampPointerDelta,
  computeCoverCropRect,
  computeRenderBufferSize,
  computeScrubFrame,
  computeScrubTime,
  stepSmoothValue,
} from './videoScrub';

test('computeScrubTime advances proportionally and clamps between 0 and duration', () => {
  const next = computeScrubTime(2.0, 100, 1000, 10, 0.8);
  assert.ok(Math.abs(next - 2.8) < 1e-9);
  assert.equal(computeScrubTime(0.2, -500, 1000, 10, 0.8), 0);
  assert.equal(computeScrubTime(9.5, 500, 1000, 10, 0.8), 10);
});

test('computeScrubFrame maps horizontal cursor delta across 97 frames with clamping', () => {
  const next = computeScrubFrame(10, 100, 1000, TOTAL_ROBOT_FRAMES, 1.0);
  assert.ok(Math.abs(next - 19.6) < 1e-6);
  assert.equal(computeScrubFrame(2, -500, 1000, TOTAL_ROBOT_FRAMES, 1.0), 0);
  assert.equal(computeScrubFrame(92, 500, 1000, TOTAL_ROBOT_FRAMES, 1.0), 96);
});

test('stepSmoothValue exponentially approaches target independent of frame rate', () => {
  const mid = stepSmoothValue(0, 50, 1 / 60, 18);
  assert.ok(mid > 10 && mid < 50);
  assert.equal(stepSmoothValue(10, 10.00001, 1 / 60, 18), 10.00001);
});

test('computeCoverCropRect respects focalXRatio when source is wider than viewport', () => {
  // 1280x724 source drawn on narrow 400x800 portrait viewport
  const leftCrop = computeCoverCropRect(400, 800, 1280, 724, 0.3, 0.5);
  const rightCrop = computeCoverCropRect(400, 800, 1280, 724, 0.7, 0.5);
  assert.equal(leftCrop.sh, 724);
  assert.equal(leftCrop.sw, 362);
  assert.ok(leftCrop.sx < rightCrop.sx);
});

test('clampPointerDelta limits extreme jumps while keeping normal deltas intact', () => {
  assert.equal(clampPointerDelta(45), 45);
  assert.equal(clampPointerDelta(600), 220);
  assert.equal(clampPointerDelta(-600), -220);
  assert.equal(clampPointerDelta(Number.NaN), 0);
});

test('computeRenderBufferSize scales cleanly up to 2x DPR and caps at 4K bounds', () => {
  assert.deepEqual(computeRenderBufferSize(1440, 900, 2), {
    width: 2880,
    height: 1800,
  });
  const capped = computeRenderBufferSize(2560, 1440, 2);
  assert.ok(capped.width <= MAX_RENDER_WIDTH && capped.height <= MAX_RENDER_HEIGHT);
});

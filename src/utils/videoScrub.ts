export const SCRUB_SENSITIVITY = 1.05;
export const FRAME_SMOOTH_SPEED = 18;
export const FOCAL_SMOOTH_SPEED = 12;
export const MAX_POINTER_DELTA_PX = 220;
export const TOTAL_ROBOT_FRAMES = 97;
export const SHEET_COLS = 3;
export const SHEET_ROWS = 3;
export const FRAMES_PER_SHEET = SHEET_COLS * SHEET_ROWS;
export const SHEET_COUNT = Math.ceil(TOTAL_ROBOT_FRAMES / FRAMES_PER_SHEET);
export const TILE_WIDTH = 1280;
export const TILE_HEIGHT = 724;
export const MAX_RENDER_WIDTH = 3840;
export const MAX_RENDER_HEIGHT = 2160;

export function clampPointerDelta(
  deltaX: number,
  maxDelta: number = MAX_POINTER_DELTA_PX,
): number {
  if (!Number.isFinite(deltaX)) return 0;
  return Math.max(-maxDelta, Math.min(maxDelta, deltaX));
}

export function computeScrubTime(
  currentTargetTime: number,
  deltaX: number,
  viewportWidth: number,
  duration: number,
  sensitivity: number = SCRUB_SENSITIVITY,
): number {
  if (!Number.isFinite(duration) || duration <= 0 || viewportWidth <= 0) {
    return 0;
  }
  const offset = (deltaX / viewportWidth) * sensitivity * duration;
  const next = currentTargetTime + offset;
  return Math.max(0, Math.min(duration, next));
}

export function computeScrubFrame(
  currentTargetFrame: number,
  deltaX: number,
  viewportWidth: number,
  totalFrames: number = TOTAL_ROBOT_FRAMES,
  sensitivity: number = SCRUB_SENSITIVITY,
): number {
  if (!Number.isFinite(totalFrames) || totalFrames <= 1 || viewportWidth <= 0) {
    return 0;
  }
  const maxIndex = totalFrames - 1;
  const offset = (deltaX / viewportWidth) * sensitivity * maxIndex;
  const next = currentTargetFrame + offset;
  return Math.max(0, Math.min(maxIndex, next));
}

export function stepSmoothValue(
  current: number,
  target: number,
  dtSeconds: number,
  speed: number = FRAME_SMOOTH_SPEED,
): number {
  if (Math.abs(target - current) < 1e-4) {
    return target;
  }
  const clampedDt = Math.max(0, Math.min(0.1, dtSeconds));
  const factor = 1 - Math.exp(-speed * clampedDt);
  return current + (target - current) * factor;
}

export function computeRenderBufferSize(
  viewportWidth: number,
  viewportHeight: number,
  devicePixelRatio: number,
): { width: number; height: number } {
  const safeW = Math.max(1, viewportWidth);
  const safeH = Math.max(1, viewportHeight);
  const dpr = Math.max(1, Math.min(devicePixelRatio || 1, 2));
  let width = Math.round(safeW * dpr);
  let height = Math.round(safeH * dpr);

  if (width > MAX_RENDER_WIDTH || height > MAX_RENDER_HEIGHT) {
    const scale = Math.min(MAX_RENDER_WIDTH / width, MAX_RENDER_HEIGHT / height);
    width = Math.max(1, Math.round(width * scale));
    height = Math.max(1, Math.round(height * scale));
  }
  return { width, height };
}

export interface CoverCropRect {
  sx: number;
  sy: number;
  sw: number;
  sh: number;
}

export function computeCoverCropRect(
  destWidth: number,
  destHeight: number,
  srcWidth: number,
  srcHeight: number,
  focalXRatio: number = 0.5,
  focalYRatio: number = 0.5,
): CoverCropRect {
  if (destWidth <= 0 || destHeight <= 0 || srcWidth <= 0 || srcHeight <= 0) {
    return { sx: 0, sy: 0, sw: srcWidth, sh: srcHeight };
  }

  const destAspect = destWidth / destHeight;
  const srcAspect = srcWidth / srcHeight;

  if (srcAspect > destAspect) {
    // Source is wider than destination: crop horizontally according to focalXRatio
    const sw = srcHeight * destAspect;
    const maxOffset = Math.max(0, srcWidth - sw);
    const sx = maxOffset * Math.max(0, Math.min(1, focalXRatio));
    return { sx, sy: 0, sw, sh: srcHeight };
  }

  // Source is taller than destination: crop vertically according to focalYRatio
  const sh = srcWidth / destAspect;
  const maxOffset = Math.max(0, srcHeight - sh);
  const sy = maxOffset * Math.max(0, Math.min(1, focalYRatio));
  return { sx: 0, sy, sw: srcWidth, sh };
}

import { useEffect, useRef } from 'react';
import {
  FOCAL_SMOOTH_SPEED,
  FRAME_SMOOTH_SPEED,
  FRAMES_PER_SHEET,
  SCRUB_SENSITIVITY,
  SHEET_COLS,
  SHEET_COUNT,
  TILE_HEIGHT,
  TILE_WIDTH,
  TOTAL_ROBOT_FRAMES,
  clampPointerDelta,
  computeCoverCropRect,
  computeRenderBufferSize,
  computeScrubFrame,
  stepSmoothValue,
} from '../utils/videoScrub';

interface BackgroundVideoProps {
  lang: 'ar' | 'en';
}

export function BackgroundVideo({ lang }: BackgroundVideoProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const ctxRef = useRef<CanvasRenderingContext2D | null>(null);
  const framesRef = useRef<Array<ImageBitmap | null>>(
    Array.from({ length: TOTAL_ROBOT_FRAMES }, () => null),
  );
  const posterRef = useRef<ImageBitmap | null>(null);

  const computeTargetFocalX = (currentLang: 'ar' | 'en') => {
    if (typeof window !== 'undefined' && window.innerWidth < 768) {
      return 0.66;
    }
    return currentLang === 'ar' ? 1.0 : 0.0;
  };

  const prevXRef = useRef<number | null>(null);
  const targetFrameRef = useRef<number>(0);
  const currentFrameRef = useRef<number>(0);
  const targetFocalXRef = useRef<number>(computeTargetFocalX(lang));
  const currentFocalXRef = useRef<number>(computeTargetFocalX(lang));
  const rafIdRef = useRef<number>(0);
  const lastTimestampRef = useRef<number>(0);
  const lastDrawnFrameRef = useRef<number>(-1);
  const lastDrawnFocalRef = useRef<number>(-1);
  const reducedMotionRef = useRef<boolean>(false);

  const drawCurrentFrame = (force: boolean = false) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = ctxRef.current ?? canvas.getContext('2d', { alpha: false });
    if (!ctx) return;
    ctxRef.current = ctx;

    // Strictly render ONE single crisp frame at a time (never blend two frames)
    const frameIdx = Math.max(
      0,
      Math.min(TOTAL_ROBOT_FRAMES - 1, Math.round(currentFrameRef.current)),
    );
    const focalX = currentFocalXRef.current;

    if (
      !force &&
      frameIdx === lastDrawnFrameRef.current &&
      Math.abs(focalX - lastDrawnFocalRef.current) < 0.0005
    ) {
      return;
    }

    const bitmap = framesRef.current[frameIdx] ?? posterRef.current;
    if (!bitmap) return;

    const crop = computeCoverCropRect(
      canvas.width,
      canvas.height,
      bitmap.width,
      bitmap.height,
      focalX,
      0.5,
    );

    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(
      bitmap,
      crop.sx,
      crop.sy,
      crop.sw,
      crop.sh,
      0,
      0,
      canvas.width,
      canvas.height,
    );

    lastDrawnFrameRef.current = frameIdx;
    lastDrawnFocalRef.current = focalX;
    canvas.dataset.frame = String(frameIdx);
  };

  const scheduleLoop = () => {
    if (rafIdRef.current !== 0) return;
    lastTimestampRef.current = performance.now();

    const tick = (now: number) => {
      const dt = Math.max(0.001, (now - lastTimestampRef.current) / 1000);
      lastTimestampRef.current = now;

      if (reducedMotionRef.current) {
        currentFrameRef.current = 0;
        currentFocalXRef.current = targetFocalXRef.current;
        drawCurrentFrame(false);
        rafIdRef.current = 0;
        return;
      }

      const nextFrame = stepSmoothValue(
        currentFrameRef.current,
        targetFrameRef.current,
        dt,
        FRAME_SMOOTH_SPEED,
      );
      const nextFocalX = stepSmoothValue(
        currentFocalXRef.current,
        targetFocalXRef.current,
        dt,
        FOCAL_SMOOTH_SPEED,
      );

      currentFrameRef.current = nextFrame;
      currentFocalXRef.current = nextFocalX;
      drawCurrentFrame(false);

      const frameSettled = Math.abs(targetFrameRef.current - nextFrame) <= 0.02;
      const focalSettled = Math.abs(targetFocalXRef.current - nextFocalX) <= 0.0005;

      if (frameSettled && focalSettled) {
        currentFrameRef.current = targetFrameRef.current;
        currentFocalXRef.current = targetFocalXRef.current;
        drawCurrentFrame(false);
        rafIdRef.current = 0;
        return;
      }

      rafIdRef.current = requestAnimationFrame(tick);
    };

    rafIdRef.current = requestAnimationFrame(tick);
  };

  // Update focal point smoothly on language toggle
  useEffect(() => {
    targetFocalXRef.current = computeTargetFocalX(lang);
    scheduleLoop();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lang]);

  useEffect(() => {
    reducedMotionRef.current =
      typeof window !== 'undefined' &&
      Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);

    const canvas = canvasRef.current;
    if (!canvas) return;
    ctxRef.current = canvas.getContext('2d', { alpha: false });
    canvas.dataset.renderer = '2d-single';

    const syncCanvasSize = () => {
      const { width, height } = computeRenderBufferSize(
        window.innerWidth,
        window.innerHeight,
        window.devicePixelRatio || 1,
      );
      const nextFocal = computeTargetFocalX(lang);
      targetFocalXRef.current = nextFocal;
      currentFocalXRef.current = nextFocal;
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        drawCurrentFrame(true);
      }
    };

    syncCanvasSize();
    window.addEventListener('resize', syncCanvasSize, { passive: true });

    let cancelled = false;

    const loadImageBitmap = async (url: string): Promise<ImageBitmap | null> => {
      try {
        const res = await fetch(url);
        if (!res.ok) return null;
        const blob = await res.blob();
        return await createImageBitmap(blob);
      } catch {
        return null;
      }
    };

    const loadPosterAndSheets = async () => {
      const poster = await loadImageBitmap('/robot-frames/poster.webp');
      if (cancelled) {
        poster?.close();
        return;
      }
      if (poster) {
        posterRef.current = poster;
        drawCurrentFrame(true);
      }

      // Load all 11 WebP sprite sheets in parallel and slice into 97 GPU-ready bitmaps
      await Promise.all(
        Array.from({ length: SHEET_COUNT }, async (_, sheetIdx) => {
          const sheetNum = String(sheetIdx + 1).padStart(2, '0');
          const sheetBitmap = await loadImageBitmap(`/robot-frames/sheet-${sheetNum}.webp`);
          if (!sheetBitmap || cancelled) {
            sheetBitmap?.close();
            return;
          }

          const startFrame = sheetIdx * FRAMES_PER_SHEET;
          const endFrame = Math.min(TOTAL_ROBOT_FRAMES, startFrame + FRAMES_PER_SHEET);

          const slicePromises: Array<Promise<void>> = [];
          for (let frameIdx = startFrame; frameIdx < endFrame; frameIdx++) {
            const localIdx = frameIdx - startFrame;
            const col = localIdx % SHEET_COLS;
            const row = Math.floor(localIdx / SHEET_COLS);
            const sx = col * TILE_WIDTH;
            const sy = row * TILE_HEIGHT;

            slicePromises.push(
              createImageBitmap(sheetBitmap, sx, sy, TILE_WIDTH, TILE_HEIGHT)
                .then((tile) => {
                  if (cancelled) {
                    tile.close();
                    return;
                  }
                  framesRef.current[frameIdx] = tile;
                })
                .catch(() => {
                  // Fallback gracefully to poster if slicing fails
                }),
            );
          }

          await Promise.all(slicePromises);
          sheetBitmap.close();
          if (!cancelled) {
            const visibleIdx = Math.max(
              0,
              Math.min(TOTAL_ROBOT_FRAMES - 1, Math.round(currentFrameRef.current)),
            );
            if (visibleIdx >= startFrame && visibleIdx < endFrame) {
              drawCurrentFrame(true);
            }
          }
        }),
      );
    };

    void loadPosterAndSheets();

    const handlePointerMove = (clientX: number) => {
      if (reducedMotionRef.current) return;
      if (prevXRef.current === null) {
        prevXRef.current = clientX;
        return;
      }

      const rawDelta = clientX - prevXRef.current;
      prevXRef.current = clientX;
      const delta = clampPointerDelta(rawDelta);
      if (delta === 0) return;

      targetFrameRef.current = computeScrubFrame(
        targetFrameRef.current,
        delta,
        window.innerWidth,
        TOTAL_ROBOT_FRAMES,
        SCRUB_SENSITIVITY,
      );
      scheduleLoop();
    };

    const resetPointerAnchor = () => {
      prevXRef.current = null;
    };

    const onMouseMove = (event: MouseEvent) => handlePointerMove(event.clientX);
    const onTouchMove = (event: TouchEvent) => {
      if (event.touches.length > 0) {
        handlePointerMove(event.touches[0].clientX);
      }
    };
    const onTouchStart = (event: TouchEvent) => {
      if (event.touches.length > 0) {
        prevXRef.current = event.touches[0].clientX;
      }
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('touchstart', onTouchStart, { passive: true });
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    document.addEventListener('mouseleave', resetPointerAnchor, { passive: true });
    window.addEventListener('blur', resetPointerAnchor, { passive: true });

    return () => {
      cancelled = true;
      if (rafIdRef.current !== 0) {
        cancelAnimationFrame(rafIdRef.current);
        rafIdRef.current = 0;
      }
      window.removeEventListener('resize', syncCanvasSize);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('touchstart', onTouchStart);
      window.removeEventListener('touchmove', onTouchMove);
      document.removeEventListener('mouseleave', resetPointerAnchor);
      window.removeEventListener('blur', resetPointerAnchor);

      ctxRef.current = null;
      posterRef.current?.close();
      posterRef.current = null;
      framesRef.current.forEach((bmp) => bmp?.close());
      framesRef.current = Array.from({ length: TOTAL_ROBOT_FRAMES }, () => null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <canvas
      ref={canvasRef}
      data-testid="robot-canvas"
      data-frame="0"
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 h-full w-full bg-[#f4f4f2]"
    />
  );
}

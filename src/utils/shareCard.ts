import type { Language, ScamCategory, Verdict } from '../types';
import { apiJson } from './api';

export interface ShareCardParams {
  score: number;
  verdict: Verdict;
  category: ScamCategory;
  lang: Language;
}

export async function downloadShareCard(params: ShareCardParams): Promise<void> {
  if (typeof document !== 'undefined' && document.fonts?.ready) {
    await document.fonts.ready;
  }

  const { svg, filename } = await apiJson<{ svg: string; filename: string }>(
    '/api/share-card',
    params,
  );
  const svgUrl = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml;charset=utf-8' }));

  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error('svg_render_error'));
      el.src = svgUrl;
    });

    const canvas = document.createElement('canvas');
    canvas.width = 1080;
    canvas.height = 1080;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.drawImage(img, 0, 0, 1080, 1080);

    const pngBlob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob((b) => resolve(b), 'image/png'),
    );
    if (!pngBlob) return;

    const pngUrl = URL.createObjectURL(pngBlob);
    const link = document.createElement('a');
    link.href = pngUrl;
    link.download = filename || `kashf-verdict-${params.score}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(pngUrl), 1500);
  } finally {
    URL.revokeObjectURL(svgUrl);
  }
}

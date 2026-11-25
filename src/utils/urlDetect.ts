export const MAX_MESSAGE_LENGTH = 5000;

const URL_DETECT_REGEX =
  /(?:https?:\/\/|www\.)[^\s<>"'\u200e\u200f\u202a-\u202e]+|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd)\/[^\s<>"'\u200e\u200f]+/gi;

export function extractUrlsFromText(text: string): string[] {
  const seen = new Set<string>();
  const matches = text.match(URL_DETECT_REGEX) ?? [];
  const cleaned: string[] = [];
  for (const raw of matches) {
    const trimmed = raw.replace(/[.,;:!?)،؛]+$/u, '');
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      cleaned.push(trimmed);
    }
  }
  return cleaned;
}

export function enforceMaxLength(
  text: string,
  maxLength: number = MAX_MESSAGE_LENGTH,
): { value: string; truncated: boolean } {
  if (text.length <= maxLength) {
    return { value: text, truncated: false };
  }
  return { value: text.slice(0, maxLength), truncated: true };
}


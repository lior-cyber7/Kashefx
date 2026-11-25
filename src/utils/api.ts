export class ApiRequestError extends Error {
  readonly code: 'rate_limit' | 'network';

  constructor(code: 'rate_limit' | 'network') {
    super(code);
    this.code = code;
  }
}

export async function apiJson<T>(url: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(
      url,
      body === undefined
        ? undefined
        : {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          },
    );
  } catch {
    throw new ApiRequestError('network');
  }
  if (res.status === 429) throw new ApiRequestError('rate_limit');
  if (!res.ok) throw new ApiRequestError('network');
  return (await res.json()) as T;
}

export function getApiErrorMessage(
  err: unknown,
  messages: { rateLimitError: string; networkError: string },
): string {
  return err instanceof ApiRequestError && err.code === 'rate_limit'
    ? messages.rateLimitError
    : messages.networkError;
}

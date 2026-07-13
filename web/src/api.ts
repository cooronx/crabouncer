let csrfToken = sessionStorage.getItem("csrf_token") ?? "";

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = init.method ?? "GET";
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD"].includes(method)) headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: "include" });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    throw new ApiError(response.status, payload?.error?.message ?? `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function login(email: string, password: string): Promise<void> {
  const result = await api<{ csrf_token: string }>("/api/v1/session", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  csrfToken = result.csrf_token;
  sessionStorage.setItem("csrf_token", csrfToken);
}

export function clearSession(): void {
  csrfToken = "";
  sessionStorage.removeItem("csrf_token");
}

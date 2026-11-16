import type { PlatformHealth, TokenResponse, User } from "@/types";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1";

export async function fetchPlatformHealth(): Promise<PlatformHealth> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Health check failed with HTTP ${response.status}`);
  }
  return response.json();
}

export async function fetchCurrentUser(token: string): Promise<User> {
  const response = await fetch(`${API_BASE_URL}/auth/me`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error("Unauthorized or expired session");
  }
  return response.json();
}

export async function loginUser(
  email: string,
  password: string
): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body?.error?.message || "Authentication failed");
  }
  return response.json();
}

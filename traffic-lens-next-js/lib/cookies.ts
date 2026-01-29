import { cookies } from "next/headers";

const isProd = process.env.NODE_ENV === "production";

export async function setAuthCookies(access: string, refresh: string) {
  const jar = await cookies();

  jar.set("access_token", access, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24, // 24h
  });

  jar.set("refresh_token", refresh, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7d
  });
}

export async function clearAuthCookies() {
  const jar = await cookies();
  jar.set("access_token", "", { path: "/", maxAge: 0 });
  jar.set("refresh_token", "", { path: "/", maxAge: 0 });
}

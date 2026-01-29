import { findUserById } from "@/db/client";
import { cookies } from "next/headers";
import {
  verifyAccessToken,
  verifyRefreshToken,
  signAccessToken,
  signRefreshToken,
} from "./jwt";
import { setAuthCookies } from "./cookies";

/**
 * Purely stateless session tokens: verifies JWT, optionally refreshes based on refresh JWT.
 * No server-side session state, no token revocation list.
 */
export async function requireUser() {
  const jar = await cookies();
  const access = jar.get("access_token")?.value;
  const refresh = jar.get("refresh_token")?.value;

  // 1) try access token
  if (access) {
    try {
      const payload = await verifyAccessToken(access);
      const user = await findUserById(payload.sub);
      if (!user) throw new Error("No user");
      return user;
    } catch {
      // fall through to refresh
    }
  }

  // 2) refresh flow
  if (!refresh) throw new Error("Unauthorized");

  const payload = await verifyRefreshToken(refresh);
  const user = await findUserById(payload.sub);
  if (!user) throw new Error("Unauthorized");

  const newPayload = { sub: user.id, email: user.email };
  const newAccess = await signAccessToken(newPayload);
  const newRefresh = await signRefreshToken(newPayload);
  setAuthCookies(newAccess, newRefresh);

  return user;
}

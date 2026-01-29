import { SignJWT, jwtVerify } from "jose";

const enc = new TextEncoder();
const accessSecret = enc.encode(process.env.JWT_ACCESS_SECRET!);
const refreshSecret = enc.encode(process.env.JWT_REFRESH_SECRET!);

const ISS = process.env.JWT_ISSUER!;
const AUD = process.env.JWT_AUDIENCE!;

export type JwtPayload = {
  sub: string;  // user id
  email: string;
};

export async function signAccessToken(payload: JwtPayload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(ISS)
    .setAudience(AUD)
    .setSubject(payload.sub)
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(accessSecret);
}

export async function signRefreshToken(payload: JwtPayload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(ISS)
    .setAudience(AUD)
    .setSubject(payload.sub)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(refreshSecret);
}

export async function verifyAccessToken(token: string) {
  const res = await jwtVerify(token, accessSecret, { issuer: ISS, audience: AUD });
  return res.payload as any as JwtPayload;
}

export async function verifyRefreshToken(token: string) {
  const res = await jwtVerify(token, refreshSecret, { issuer: ISS, audience: AUD });
  return res.payload as any as JwtPayload;
}
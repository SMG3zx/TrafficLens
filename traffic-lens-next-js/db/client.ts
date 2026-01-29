import crypto from "node:crypto";
import { createClient } from "@libsql/client";

const db = createClient({
    url: "file:local.db",
});


export type UserRow = {
  id: string;
  email: string;
  passwordHash: string;
  emailVerifiedAt: string | null;

  emailVerifyHash: string | null;
  emailVerifyExpires: string | null;

  resetHash: string | null;
  resetExpires: string | null;

  pendingEmail: string | null;
  emailChangeHash: string | null;
  emailChangeExpires: string | null;

  createdAt: string;
  updatedAt: string;
};

function toUser(row: any): UserRow {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.passwordHash,
    emailVerifiedAt: row.emailVerifiedAt ?? null,

    emailVerifyHash: row.emailVerifyHash ?? null,
    emailVerifyExpires: row.emailVerifyExpires ?? null,

    resetHash: row.resetHash ?? null,
    resetExpires: row.resetExpires ?? null,

    pendingEmail: row.pendingEmail ?? null,
    emailChangeHash: row.emailChangeHash ?? null,
    emailChangeExpires: row.emailChangeExpires ?? null,

    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

// Prisma used cuid(); use your own. Keep it simple and URL-safe.
export function newId(): string {
  return crypto.randomBytes(16).toString("hex");
}

export function nowIso(): string {
  return new Date().toISOString();
}

export async function createUser(input: {
  email: string;
  passwordHash: string;
}): Promise<UserRow> {
  const id = newId();

  await db.execute({
    sql: `
      INSERT INTO User (
        id, email, passwordHash,
        emailVerifiedAt,
        emailVerifyHash, emailVerifyExpires,
        resetHash, resetExpires,
        pendingEmail, emailChangeHash, emailChangeExpires
      )
      VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
    `,
    args: [id, input.email, input.passwordHash],
  });

  const user = await findUserById(id);
  if (!user) throw new Error("Failed to create user");
  return user;
}

export async function findUserById(id: string): Promise<UserRow | null> {
  const res = await db.execute({
    sql: `SELECT * FROM User WHERE id = ? LIMIT 1`,
    args: [id],
  });
  return res.rows[0] ? toUser(res.rows[0]) : null;
}


// Email verification flow
export async function findUserByEmail(email: string): Promise<UserRow | null> {
  const res = await db.execute({
    sql: `SELECT * FROM User WHERE email = ? LIMIT 1`,
    args: [email],
  });
  return res.rows[0] ? toUser(res.rows[0]) : null;
}


export async function setEmailVerification(
  userId: string,
  verifyHash: string,
  expiresIso: string
): Promise<void> {
  await db.execute({
    sql: `
      UPDATE User
      SET emailVerifyHash = ?, emailVerifyExpires = ?
      WHERE id = ?
    `,
    args: [verifyHash, expiresIso, userId],
  });
}

export async function findUserByEmailVerifyHash(hash: string): Promise<UserRow | null> {
  const res = await db.execute({
    sql: `SELECT * FROM User WHERE emailVerifyHash = ? LIMIT 1`,
    args: [hash],
  });
  return res.rows[0] ? toUser(res.rows[0]) : null;
}

export async function verifyEmailByHash(hash: string): Promise<void> {
  // sets verified time and clears verify fields
  await db.execute({
    sql: `
      UPDATE User
      SET
        emailVerifiedAt = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        emailVerifyHash = NULL,
        emailVerifyExpires = NULL
      WHERE emailVerifyHash = ?
    `,
    args: [hash],
  });
}

// Password reset flow
export async function setPasswordReset(
  userId: string,
  resetHash: string,
  expiresIso: string
): Promise<void> {
  await db.execute({
    sql: `
      UPDATE User
      SET resetHash = ?, resetExpires = ?
      WHERE id = ?
    `,
    args: [resetHash, expiresIso, userId],
  });
}

export async function findUserByResetHash(hash: string): Promise<UserRow | null> {
  const res = await db.execute({
    sql: `SELECT * FROM User WHERE resetHash = ? LIMIT 1`,
    args: [hash],
  });
  return res.rows[0] ? toUser(res.rows[0]) : null;
}

export async function completePasswordReset(
  resetHash: string,
  newPasswordHash: string
): Promise<void> {
  // updates password and clears reset fields
  await db.execute({
    sql: `
      UPDATE User
      SET
        passwordHash = ?,
        resetHash = NULL,
        resetExpires = NULL
      WHERE resetHash = ?
    `,
    args: [newPasswordHash, resetHash],
  });
}
// Email change flow
export async function startEmailChange(
  userId: string,
  pendingEmail: string,
  changeHash: string,
  expiresIso: string
): Promise<void> {
  await db.execute({
    sql: `
      UPDATE User
      SET pendingEmail = ?, emailChangeHash = ?, emailChangeExpires = ?
      WHERE id = ?
    `,
    args: [pendingEmail, changeHash, expiresIso, userId],
  });
}

export async function findUserByEmailChangeHash(hash: string): Promise<UserRow | null> {
  const res = await db.execute({
    sql: `SELECT * FROM User WHERE emailChangeHash = ? LIMIT 1`,
    args: [hash],
  });
  return res.rows[0] ? toUser(res.rows[0]) : null;
}

export async function confirmEmailChange(hash: string): Promise<void> {
  // moves pendingEmail -> email, clears change fields
  // note: email is UNIQUE; if pendingEmail already exists this will throw
  await db.execute({
    sql: `
      UPDATE User
      SET
        email = pendingEmail,
        pendingEmail = NULL,
        emailChangeHash = NULL,
        emailChangeExpires = NULL
      WHERE emailChangeHash = ?
    `,
    args: [hash],
  });
}

// Basic account Settings
export async function updatePasswordHash(userId: string, passwordHash: string): Promise<void> {
  await db.execute({
    sql: `UPDATE User SET passwordHash = ? WHERE id = ?`,
    args: [passwordHash, userId],
  });
}

export async function deleteUser(userId: string): Promise<void> {
  await db.execute({
    sql: `DELETE FROM User WHERE id = ?`,
    args: [userId],
  });
}
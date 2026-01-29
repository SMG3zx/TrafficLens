import { z } from "zod";

export const SignupSchema = z.object({
  email: z.email(),
  password: z.string().min(8).max(200),
});

export const LoginSchema = z.object({
  email: z.email(),
  password: z.string().min(1),
});

export const TokenSchema = z.object({
  token: z.string().min(10),
});

export const ForgotSchema = z.object({
  email: z.email(),
});

export const ResetSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(8).max(200),
});

export const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8).max(200),
});

export const ChangeEmailSchema = z.object({
  newEmail: z.email(),
  currentPassword: z.string().min(1),
});

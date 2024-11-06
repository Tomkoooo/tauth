// src/api/next/auth/reset-password/route.ts

import { NextResponse } from 'next/server';
import {  resetPassword } from '../../../../auth';

export async function POST(req: Request) {
  const { email, code, newPassword } = await req.json();
  try {
    await resetPassword(email, code, newPassword);
    return NextResponse.json({ message: 'Password reset email sent' });
  } catch (error: any) {
    return NextResponse.json({ message: error.message }, { status: 400 });
  }
}

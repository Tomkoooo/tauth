// src/api/next/auth/forgot-password/route.ts

import { NextResponse } from 'next/server';
import { requestPasswordReset } from '../../../../auth';

export async function POST(req: Request) {
  const { email } = await req.json();
  try {
    await requestPasswordReset(email);
    return NextResponse.json({ message: 'Password reset email sent' });
  } catch (error: any) {
    return NextResponse.json({ message: error.message }, { status: 400 });
  }
}

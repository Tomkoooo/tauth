// src/api/next/auth/register/route.ts

import { NextResponse } from 'next/server';
import { registerUser } from '../../../../auth';  // Register user logic

export async function POST(req: Request) {
  const { email, password } = await req.json();

  try {
    const { user } = await registerUser(email, password);
    return NextResponse.json({ message: 'User registered successfully', user });
  } catch (error: any) {
    return NextResponse.json({ message: error.message }, { status: 400 });
  }
}

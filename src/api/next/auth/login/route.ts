// src/api/next/auth/login/route.ts

import { NextResponse } from 'next/server';
import { loginUser } from '../../../../auth';  // Import loginUser function

export async function POST(req: Request) {
  const { email, password } = await req.json();

  try {
    const { token, user } = await loginUser(email, password);
    return NextResponse.json({ token, user });
  } catch (error: any) {
    return NextResponse.json({ message: error.message }, { status: 401 });
  }
}

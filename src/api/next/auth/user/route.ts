// src/api/next/auth/user/route.ts

import { NextResponse, NextRequest } from 'next/server';
import { getUser } from '../../../../auth';  // Get user by token logic

export async function GET(req: NextRequest) {
  const token = req.headers.get('authorization')?.split(' ')[1] || '';

  try {
    const clientIp = req.headers.get('x-forwarded-for')
    const user = await getUser(token, clientIp as string);

    if (user) {
      return NextResponse.json(user);
    } else {
      return NextResponse.json({ message: 'User not found' }, { status: 401 });
    }
  } catch (error) {
    return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
  }
}

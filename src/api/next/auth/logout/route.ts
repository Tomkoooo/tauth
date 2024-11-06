// src/api/next/auth/logout/route.ts

import { NextResponse } from 'next/server';
import { connectToDatabase } from '../../../../db/mongodb';

export async function POST(req: Request) {
    const {email} = await req.json();
    const db  = await connectToDatabase();
    const users = db.collection('users');
    const user = await users.findOne
    ({email: email});
    if (!user) {
        return NextResponse.json({message: 'User not found'}, {status: 404});
    }
    await users.updateOne({email: email}, {$set: {'codes.token': ''}});
    return NextResponse.json({ message: 'User logged out successfully' }, { status: 200 });
}



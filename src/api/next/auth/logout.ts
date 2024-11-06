// src/api/next/auth/logout.ts

import { NextApiRequest, NextApiResponse } from 'next';
import { connectToDatabase } from '../../../db/mongodb';

export default async function logout(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    // Clear token (in cookies, session, or database)
    const {email} = await req.body();
    const db  = await connectToDatabase();
    const users = db.collection('users');
    const user = await users.findOne
    ({email: email});
    if (!user) {
        res.status(404).json({message: 'User not found'});
    }
    res.setHeader('Set-Cookie', 'token=; HttpOnly; Path=/; Max-Age=0'); // Example cookie reset
    res.status(200).json({ message: 'User logged out successfully' });
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

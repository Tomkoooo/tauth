// src/api/next/auth/register.ts

import { NextApiRequest, NextApiResponse } from 'next';
import { registerUser } from '../../../auth';  // Register user logic

export default async function register(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { email, password } = req.body;
    
    try {
      const { user } = await registerUser(email, password);
      res.status(200).json({ message: 'User registered successfully', user });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

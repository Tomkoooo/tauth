// src/api/next/auth/login.ts

import { NextApiRequest, NextApiResponse } from 'next';
import { loginUser } from '../../../auth';

export default async function login(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { email, password } = req.body;
    
    try {
      const { token, user } = await loginUser(email, password);
      res.status(200).json({ token, user });
    } catch (error: any) {
      res.status(401).json({ message: error.message });
    }
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

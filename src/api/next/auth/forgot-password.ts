// src/api/next/auth/forgot-password.ts

import { NextApiRequest, NextApiResponse } from 'next';
import { requestPasswordReset } from '../../../auth';

export default async function forgotPassword(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { email } = req.body;
    const resetCode = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit code
    try {
      await requestPasswordReset(email);
      res.status(200).json({ message: 'Password reset email sent' });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

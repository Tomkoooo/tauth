// src/api/next/auth/forgot-password.ts

import { NextApiRequest, NextApiResponse } from 'next';
import { resetPassword } from '../../../auth';

export default async function forgotPassword(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { email, code, newPassword } = req.body;
    try {
      await resetPassword(email, code, newPassword);
      res.status(200).json({ message: 'Password reseted.' });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

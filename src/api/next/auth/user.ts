// src/api/next/auth/user.ts

import { NextApiRequest, NextApiResponse } from 'next';
import { getUser } from '../../../auth';  // Get user by token logic

export default async function user(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    const token = req.headers['authorization']?.split(' ')[1] || '';

    try {
      const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      const user = await getUser(token, clientIp as string);

      if (user) {
        res.status(200).json(user);
      } else {
        res.status(401).json({ message: 'User not found' });
      }
    } catch (error) {
      res.status(401).json({ message: 'Unauthorized' });
    }
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

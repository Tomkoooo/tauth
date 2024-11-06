import express, { Request, Response } from 'express';
import { loginUser, getUser, registerUser, resetPassword, requestPasswordReset } from '../../auth';
import { connectToDatabase } from '../../db/mongodb';

const router = express.Router();

// POST login route
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const { token, user } = await loginUser(email, password);
    res.json({ token, user });
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// GET user route
router.get('/getUser', async (req: Request, res: Response) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from header
    if (!token) {
      res.status(400).json({ message: 'No token provided' });
      return;
    }
    const user = await getUser(token);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    res.json(user);
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// POST register route
router.post('/register', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await registerUser(email, password); // Implement registration logic in auth.ts
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// POST forgot-password route (request reset)
router.post('/forgot-password', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const result = await requestPasswordReset(email); // Implement the logic in auth.ts
    if (result) {
      res.status(200).json({ message: 'Password reset email sent successfully' });
    } else {
      res.status(400).json({ message: 'Email not found' });
    }
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// POST reset-password route (actual password reset)
router.post('/reset-password', async (req: Request, res: Response) => {
  try {
    const { token, resetCode, newPassword } = req.body;
    const result = await resetPassword(token, resetCode, newPassword); // Implement reset logic in auth.ts
    if (result) {
      res.status(200).json({ message: 'Password reset successfully' });
    } else {
      res.status(400).json({ message: 'Invalid or expired reset token' });
    }
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// POST logout route (invalidate session or token)
router.post('/logout', async (req: Request, res: Response) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      res.status(400).json({ message: 'No token provided' });
      return;
    }
    const {email} = await req.body();
    const db  = await connectToDatabase();
    const users = db.collection('users');
    const user = await users.findOne
    ({email: email});
    if (!user) {
        res.status(404).json({message: 'User not found'});
    }
    await users.updateOne({email: email}, {$set: {'codes.token': ''}});
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

export default router;

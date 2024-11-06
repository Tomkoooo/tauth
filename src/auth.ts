// src/auth.ts
import { connectToDatabase } from './db/mongodb';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { ObjectId } from 'mongodb';
import { sendVerificationEmail, sendPasswordResetEmail } from './emailService/emailService'; // External email service
import { loadAuthOptions } from './utils/authOptions';
import { loadExtendedSchema } from './utils/userSchema';
import { getClientIp } from './utils/getClientIp'; // Import the IP utility function

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const userSchema = loadExtendedSchema();
const authOptions = loadAuthOptions();

function generateToken(userId: string, clientIp: string) {
    const payload = { userId, ip: clientIp };
    const options = { expiresIn: '24h' };
    return jwt.sign(payload, JWT_SECRET, options);
}

export async function registerUser(email: string, password: string) {
  const db = await connectToDatabase();
  const existingUser = await db.collection('users').findOne({ email });

  if (existingUser) throw new Error('User already exists');

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationCode = Math.floor(100000 + Math.random() * 900000);
  const newUser = {
    ...userSchema,
    email,
    password: hashedPassword,
    codes: { verification: verificationCode }
  };

  await db.collection('users').insertOne(newUser);

  if (authOptions.requireEmailVerification) {
    await sendVerificationEmail(email, verificationCode);
    return {user: newUser, success: true, message: 'Registration successful. Please verify your email if required.' };
  }

  return { user: newUser, success: true, message: 'Registration successful'}
}

export async function loginUser(identifier: string, password: string) {
    const db = await connectToDatabase();
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Determine the query based on the selected auth method
    let userQuery = {};
    if (authOptions.authMethod === 'email') {
      userQuery = { email: identifier };
    } else if (authOptions.authMethod === 'username') {
      userQuery = { username: identifier };
    } else if (authOptions.authMethod === 'both') {
      userQuery = { $or: [{ email: identifier }, { username: identifier }] };
    }
  
    // Find user by email, username, or both
    const user = await db.collection('users').findOne(userQuery);
  
    if (!user || !(await bcrypt.compare(password, hashedPassword))) {
      throw new Error('Invalid credentials');
    }
  
    // Check email verification if required
    if (authOptions.requireEmailVerification && !user.verified) {
      throw new Error('Email verification is required');
    }
  
    // Fetch the client IP
    const clientIp = await getClientIp();
    if (!clientIp) {
      throw new Error('Could not retrieve client IP');
    }
  
    // Generate a token with IP and update session info in the database
    const token = generateToken(user._id.toString(), clientIp);
    await db.collection('users').updateOne(
      { _id: new ObjectId(user._id) },
      { $set: { 'codes.sessionId': token } }
    );
  
    return { token: jwt.sign(user._id.toString(), JWT_SECRET), user };
  }
  

export async function verifyEmail(email: string, verificationCode: number) {
  const db = await connectToDatabase();
  const user = await db.collection('users').findOne({ email });

  if (!user || user.codes.verification !== verificationCode) {
    throw new Error('Invalid verification code');
  }

  await db.collection('users').updateOne(
    { email },
    { $set: { verified: true }, $unset: { "codes.verification": "" } }
  );

  return { success: true, message: 'Email verified successfully' };
}

// Password reset request
export async function requestPasswordReset(email: string) {
  const db = await connectToDatabase();
  const user = await db.collection('users').findOne({ email });

  if (!user) throw new Error('User not found');

  const resetCode = Math.floor(100000 + Math.random() * 900000);
  await db.collection('users').updateOne(
    { email },
    { $set: { "codes.reset": resetCode } }
  );

  await sendPasswordResetEmail(email, resetCode);
  return { success: true, message: 'Password reset code sent to email' };
}

export async function resetPassword(email: string, resetCode: number, newPassword: string) {
  const db = await connectToDatabase();
  const user = await db.collection('users').findOne({ email });

  if (!user || user.codes.reset !== resetCode) {
    throw new Error('Invalid reset code');
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await db.collection('users').updateOne(
    { email },
    { $set: { password: hashedPassword }, $unset: { "codes.reset": "" } }
  );

  return { success: true, message: 'Password reset successfully' };
}

export async function getUser(token: string, ip?: string) {
    try {
      // Fetch the client IP if not provided
      const clientIp = ip || await getClientIp();
      if (!clientIp) throw new Error('Could not retrieve client IP');
  
      // Decode the token to extract the user ID and IP
      const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; ip: string };
  
      // Connect to the database
      const db = await connectToDatabase();
  
      // Verify the IP addresses match (either the one stored in the token or provided as a parameter)
      if (decoded.ip !== clientIp) {
        throw new Error('IP address mismatch');
      }
  
      // Find the user in the database using the sessionId (the token)
      const user = await db.collection('users').findOne({ 'codes.sessionId': token });
      if (!user) throw new Error('User not found');
  
      return user; // Return the user data
    } catch (error) {
      console.error(error);
      return null; // Return null if there's an error or user is not found
    }
  }

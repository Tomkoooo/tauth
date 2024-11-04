// src/auth.ts
import { connectToDatabase } from './db/mongodb';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { ObjectId } from 'mongodb';
import { sendVerificationEmail, sendPasswordResetEmail } from './emailService/emailService'; // Külső email service
import { loadAuthOptions } from './utils/authOptions';
import { loadExtendedSchema } from './utils/userSchema';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const userSchema = loadExtendedSchema();
const authOptions = loadAuthOptions();

function generateToken(userId: string) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
}

// Felhasználó regisztráció e-mail verifikációval
export async function registerUser(email: string, password: string) {
  const db = await connectToDatabase();
  const existingUser = await db.collection('users').findOne({ email });
  
  if (existingUser) {
    throw new Error('User already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationCode = Math.floor(100000 + Math.random() * 900000); // 6 jegyű kód
  const newUser = {
    ...userSchema,
    email,
    password: hashedPassword,
    codes: { verification: verificationCode }
  };

  await db.collection('users').insertOne(newUser);

  if (authOptions.requireEmailVerification) {
    await sendVerificationEmail(email, verificationCode);
  }

  return { success: true, message: 'Registration successful. Please verify your email if required.' };
}

// Bejelentkezés e-mail verifikációval
export async function loginUser(email: string, password: string) {
  const db = await connectToDatabase();
  const user = await db.collection('users').findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    throw new Error('Invalid email or password');
  }

  if (authOptions.requireEmailVerification && !user.verified) {
    throw new Error('Email verification is required');
  }

  const token = generateToken(user._id.toString());
  return { token, user };
}

// E-mail verifikáció ellenőrzése
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

// Jelszó visszaállítás kérés
export async function requestPasswordReset(email: string) {
  const db = await connectToDatabase();
  const user = await db.collection('users').findOne({ email });

  if (!user) throw new Error('User not found');

  const resetCode = Math.floor(100000 + Math.random() * 900000); // 6 jegyű kód
  await db.collection('users').updateOne(
    { email },
    { $set: { "codes.reset": resetCode } }
  );

  await sendPasswordResetEmail(email, resetCode);
  return { success: true, message: 'Password reset code sent to email' };
}

// Jelszó visszaállítás ellenőrzése
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

// Szerveroldali `getUser` függvény az autentikációhoz
export async function getUser(token: string, clientIp: string) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; ip: string };
    if (decoded.ip !== clientIp) throw new Error('IP address mismatch');

    const db = await connectToDatabase();
    const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.userId) });
    if (!user) throw new Error('User not found');

    return user; // Visszaadja a felhasználói adatokat, ha érvényes a token
  } catch (error) {
    console.error(error);
    return null;
  }
}
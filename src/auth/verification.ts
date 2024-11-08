// src/auth/verification.ts

'use server'

import { connectToDatabase } from "../db/mongodb";
import { sendVerificationEmail } from "../emailService/sendVerifcationEmail";
import { generateVerificationCode } from "../utils/otp";
import bcrypt from "bcryptjs";

export const verifyEmail = async (email: string, verificationCode: number) => {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const user = await users.findOne({ email})

    if (!user || user.codes.verification !== verificationCode) {
        throw new Error("User not found, or verification code does not match.");
    }

    await users.updateOne(
        {email},
        {
            $set: {
                verified: true,
                'codes.verification': null
            }
        }
    )
    return {success: true, message: "Email verified."}
}

export const resendVerificationEmail = async (email: string) => {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const user = await users.findOne({ email})

    if (!user){
        throw new Error("User not found.")
    }

    const verificationCode = await generateVerificationCode(user._id.toString(), "verification")
    await sendVerificationEmail(email, verificationCode) 

    return {success: true, message: "Verification email sent."}
}

export const requestPasswordReset = async (email: string) => {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const user = await users.findOne({ email})

    if (!user){
        throw new Error("User not found.")
    }

    const resetCode = await generateVerificationCode(user._id.toString(), "reset")
    await sendVerificationEmail(email, resetCode)

    return {success: true, message: "Password reset email sent."}
}

export const resetPassword = async (email: string, resetCode: number, newPassword: string) => {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const user = await users.findOne({ email})

    if (!user || user.codes.reset !== resetCode) {
        throw new Error("User not found, or reset code does not match.")
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10)
    await users.updateOne(
        {email},
        {
            $set: {
                password: hashedPassword,
                'codes.reset': null
            }
        }
    )

    return {success: true, message: "Password reset.", user: user}
}
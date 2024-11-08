// src/auth/register.ts

'use server'

import { connectToDatabase } from "../db/mongodb";
import bcrypt from "bcryptjs";
import { generateVerificationCode } from "../utils/otp";
import { userSchemaOptions, authOptions } from "../utils/options";
import { sendVerificationEmail } from "../emailService/sendVerifcationEmail";
import { generateToken } from "../utils/generateToken";
import { getClientIp } from "../utils/getClientIp";

export async function registerUser(email: string, password: string) {
    try {
        const db = await connectToDatabase();
    const users = db.collection("users");

    const existingUser = await users.findOne({ email});

    if (existingUser) {
        throw new Error("User already exists.");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        ...userSchemaOptions(),
        email,
        password: hashedPassword,
        }

        const insertedUser = await users.insertOne(newUser)

        if(authOptions().verifcationRequired){
            const verificationCode = await generateVerificationCode(insertedUser.insertedId.toString(), "verification")
            sendVerificationEmail(email, verificationCode)
            return {success: true, message: "User created. Verification email sent.", user: newUser}
        }

        const ip = getClientIp()

        const token = generateToken(insertedUser.insertedId.toString(), ip.toString())

        return {success: true, message: "User created.", user: newUser, token: token.hashedUserId}
        } catch (error: any) {
            return {success: false, message: error.message, user: {}}
        }

  }

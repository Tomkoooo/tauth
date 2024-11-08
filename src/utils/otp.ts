// src/utils/verification.ts
'use server'
import { connectToDatabase } from "../db/mongodb"
import { ObjectId } from "mongodb";

export const generateVerificationCode = async (userId: string, verificationMethod: string) => {
    const code = Math.floor(100000 + Math.random() * 900000) //returns a random 6 digit number;
    const db = await connectToDatabase();
    const users = db.collection("users");

    const user = await users.findOne({ _id: new ObjectId(userId) });
    if (!user) {
        throw new Error("User not found.");
    }

    await users.updateOne(
        { _id: new ObjectId(userId) },
        {
            $set: {
                [`codes.${verificationMethod}`]: code
            }
        }
    )

    return code;
}
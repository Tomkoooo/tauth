// src/auth/getUser.ts
'use server'
import { connectToDatabase } from "../db/mongodb";
import { getClientIp } from "../utils/getClientIp";
import jwt from "jsonwebtoken";
import { validateToken } from "../utils/generateToken";

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

export const getUser = async (token: string, ip?: string | null) => {
    try {
        const db = await connectToDatabase();
        const users = db.collection("users");

        // Retrieve client IP, either provided directly or from another utility function
        const clientIp = ip || getClientIp();
        if (!clientIp) {
            throw new Error("Could not get client IP.");
        }

        // Decode the JWT to extract the userId
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
        const userId = decoded.userId;

        // Use validateToken to verify that the token is valid for the userId and clientIp
        const isValidToken = validateToken(token, userId, clientIp);
        if (!isValidToken) {
            throw new Error("Invalid token.");
        }

        // If token is valid, query the user in the database by userId
        const user = await users.findOne({ userId });
        if (!user) {
            throw new Error("User not found.");
        }

        // Return user data if found
        return {success: true, user};
    } catch (error) {
        console.error("Error fetching user:", error);
        throw new Error("Unable to authenticate user.");
    }
};

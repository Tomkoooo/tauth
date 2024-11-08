// src/auth/login.ts

'use server'

import { connectToDatabase } from "../db/mongodb"
import bcrypt from "bcryptjs"
import { getClientIp } from "../utils/getClientIp"
import { generateToken } from "../utils/generateToken"
import { authOptions } from "../utils/options"

export async function loginUser(identifier: string, password: string) {
    try {
        const db = await connectToDatabase()
        const users = db.collection("users")
        const options = authOptions()
        const hashedPassword = await bcrypt.hash(password, 10)

        let query = {}
        if (options.authMethod === "email") {
            query = { email: identifier }
        } else if (options.authMethod === "username") {
            query = { username: identifier }
        } else if (options.authMethod === "both") {
            query = { $or: [{ email: identifier }, { username: identifier }] }
        }

        const user = await users.findOne(query)

        if (!user || !(await bcrypt.compare(hashedPassword, user.password))) {
            throw new Error("Invalid credentials.")
        }

        if (options.verifcationRequired && !user.verified) {
            throw new Error("Email verification required.")
        }

        const clientIp = getClientIp()
        if(!clientIp) {
            throw new Error("Could not get client IP.")
        }

        const token = generateToken(user._id.toString(), clientIp.toString())
        await users.updateOne({ _id: user._id }, { $set: { 'codes.token': token.token } })

        return { success: true, message: "User logged in.", token: token.hashedUserId, user: user }

    } catch (error: any) {
        return {success: false, message: error.message, token: ""}
    }
}
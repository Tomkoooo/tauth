// src/emailService/sendVerifcationEmail.ts

'use server'

import { sendMail } from "./mailer";
import { emailOptions } from "../utils/options";

export const sendVerificationEmail = async (to: string, code: number) => {
    const { html, subject } = emailOptions();
    const emailHtml = html.replace(/{{code}}/g, code.toString());
    await sendMail(to, subject, emailHtml);
    return
}
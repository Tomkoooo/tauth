// src/emailService.ts
import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';

// SMTP hitelesítő adatok betöltése környezeti változókból
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false, // true, ha 465-öt használsz, false, ha 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// E-mail tartalom betöltése auth.options.json-ból
const loadEmailOptions = () => {
  const optionsPath = path.resolve(process.cwd(), 'auth.options.json');
  if (fs.existsSync(optionsPath)) {
    return JSON.parse(fs.readFileSync(optionsPath, 'utf-8'));
  }
  return {};
};

const emailOptions = loadEmailOptions();

// E-mail verifikációs e-mail küldése
export const sendVerificationEmail = async (to: string, verificationCode: number) => {
  const { subject, html } = emailOptions.verificationEmail;

  const emailHtml = html.replace('{{code}}', verificationCode.toString());

  await transporter.sendMail({
    from: process.env.SMTP_USER, // sender address
    to, // list of receivers
    subject, // Subject line
    html: emailHtml, // html body
  });
};

// Jelszó visszaállítási e-mail küldése
export const sendPasswordResetEmail = async (to: string, resetCode: number) => {
  const { subject, html } = emailOptions.passwordResetEmail;

  const emailHtml = html.replace('{{code}}', resetCode.toString());

  await transporter.sendMail({
    from: process.env.SMTP_USER, // sender address
    to, // list of receivers
    subject, // Subject line
    html: emailHtml, // html body
  });
};

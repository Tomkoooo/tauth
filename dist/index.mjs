// src/db/mongodb.ts
import { MongoClient } from "mongodb";
var client = null;
var connectToDatabase = async () => {
  const mongoUri = process.env.MONGO_URI;
  const dbName = process.env.MONGO_DB_NAME;
  if (!mongoUri) {
    throw new Error("MONGO_URI env variable is missing.");
  }
  if (!dbName) {
    throw new Error("MONGO_DB_NAME env variable is missing.");
  }
  if (!client) {
    client = new MongoClient(mongoUri);
    await client.connect();
  }
  return client.db(dbName);
};

// src/utils/generateToken.ts
import jwt from "jsonwebtoken";
import crypto from "crypto";
var JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
var EXPIRES_IN = process.env.JWT_EXPIRES_IN || "24h";
function generateToken(userId, clientIp) {
  const hashedUserId = hash(userId + JWT_SECRET);
  const hashedClientIp = hash(clientIp + JWT_SECRET);
  const token = jwt.sign(
    { hash: hash(userId + clientIp + JWT_SECRET) },
    JWT_SECRET,
    { expiresIn: EXPIRES_IN }
  );
  return {
    token,
    hashedUserId,
    hashedClientIp
  };
}
function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
function validateToken(token, userId, clientIp) {
  try {
    if (!clientIp) return false;
    const decoded = jwt.verify(token, JWT_SECRET);
    const expectedHash = hash(userId + clientIp + JWT_SECRET);
    return decoded.hash === expectedHash;
  } catch (err) {
    console.error("Token validation error:", err);
    return false;
  }
}

// src/utils/options.ts
import fs from "fs";
import path from "path";
var emailOptions = () => {
  const defaultEmailTemplate = {
    html: "Please use the following code to verify your email: <strong>{{code}}</strong>",
    subject: "Email verification code"
  };
  const optionsPath = path.resolve(process.cwd(), "auth.options.json");
  if (!fs.existsSync(optionsPath)) {
    return defaultEmailTemplate;
  }
  const options = fs.readFileSync(optionsPath, "utf-8");
  return JSON.parse(options).emailTemplate;
};
var userSchemaOptions = () => {
  const defaultUserSchema = {
    name: "",
    email: "",
    password: "",
    role: "user",
    verified: false,
    codes: {
      reset: null,
      token: null,
      verification: null
    }
  };
  const optionsPath = path.resolve(process.cwd(), "auth.schema.json");
  if (!fs.existsSync(optionsPath)) {
    return defaultUserSchema;
  }
  const options = fs.readFileSync(optionsPath, "utf-8");
  return { ...defaultUserSchema, ...JSON.parse(options).userSchema };
};
var authOptions = () => {
  const defaultOptions = {
    verifcationRequired: false,
    authMethod: "both"
  };
  const optionsPath = path.resolve(process.cwd(), "auth.options.json");
  if (!fs.existsSync(optionsPath)) {
    return defaultOptions;
  }
  const options = fs.readFileSync(optionsPath, "utf-8");
  return JSON.parse(options).authOptions;
};
var routesOptions = () => {
  const routeOptionsPath = path.resolve(process.cwd(), "auth.routes.json");
  if (!fs.existsSync(routeOptionsPath)) {
    return null;
  }
  const routeOptions = fs.readFileSync(routeOptionsPath, "utf-8");
  return JSON.parse(routeOptions);
};

// src/utils/otp.ts
import { ObjectId } from "mongodb";
var generateVerificationCode = async (userId, verificationMethod) => {
  const code = Math.floor(1e5 + Math.random() * 9e5);
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
  );
  return code;
};

// src/types/user.ts
var User = userSchemaOptions();

// src/middlewere/appRouterMidlewere.ts
import { NextResponse } from "next/server";

// src/utils/getClientIp.ts
async function getClientIp() {
  try {
    const response = await fetch("https://api64.ipify.org?format=json");
    if (!response.ok) throw new Error("Failed to fetch IP");
    const data = await response.json();
    return data.ip;
  } catch (error) {
    console.error("Could not retrieve client IP:", error);
    return null;
  }
}

// src/auth/getUser.ts
import jwt2 from "jsonwebtoken";
var JWT_SECRET2 = process.env.JWT_SECRET || "your_jwt_secret";
var getUser = async (token, ip) => {
  try {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const clientIp = ip || getClientIp();
    if (!clientIp) {
      throw new Error("Could not get client IP.");
    }
    const decoded = jwt2.verify(token, JWT_SECRET2);
    const userId = decoded.userId;
    const isValidToken = validateToken(token, userId, clientIp);
    if (!isValidToken) {
      throw new Error("Invalid token.");
    }
    const user = await users.findOne({ userId });
    if (!user) {
      throw new Error("User not found.");
    }
    return { success: true, user };
  } catch (error) {
    console.error("Error fetching user:", error);
    throw new Error("Unable to authenticate user.");
  }
};

// src/middlewere/appRouterMidlewere.ts
import { cookies } from "next/headers";
async function appRouterMiddleware(req) {
  const ip = req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for");
  const { pathname } = req.nextUrl;
  const cookieToken = (await cookies()).get("token")?.value?.toString() || "";
  const session = await getUser(cookieToken, ip);
  const routes = routesOptions();
  let routeConfig;
  if (routes) {
    routeConfig = routes.routes[pathname];
  }
  if (routeConfig) {
    if (routeConfig.type === "public") {
      return NextResponse.next();
    }
    if (routeConfig.type === "private" && routeConfig.credentials && routeConfig.redirectTo) {
      if (session.success) {
        const user = session.user;
        const condition = new Function("user", `return ${routeConfig.credentials}`);
        if (condition(user)) {
          return NextResponse.next();
        } else {
          return NextResponse.redirect(new URL(routeConfig.redirectTo, req.url));
        }
      } else {
        return NextResponse.redirect(new URL(routeConfig.redirectTo, req.url));
      }
    }
  }
  return NextResponse.next();
}
var config = {
  matcher: Object.keys(routesOptions().routes).map((path2) => path2.startsWith("/") ? path2 : `/${path2}`)
};

// src/middlewere/pagesRouterMidllewere.ts
import { NextResponse as NextResponse2 } from "next/server";
var secret = new TextEncoder().encode(process.env.JWT_SECRET || "your-secret-key");
async function pagesRouterMiddlewere(req) {
  const { pathname } = req.nextUrl;
  const forwarded = req.headers.get("x-forwarded-for");
  const ip = forwarded ? forwarded.split(",")[0] : req.headers.get("x-real-ip") || req.nextUrl.hostname;
  const cookieToken = req.cookies.get("token")?.value || "";
  const routes = routesOptions();
  const session = await getUser(cookieToken, ip);
  const routeConfig = routes?.routes?.[pathname];
  if (!routeConfig) return NextResponse2.next();
  if (routeConfig.type === "public") return NextResponse2.next();
  if (routeConfig.type === "private") {
    if (!cookieToken) {
      return NextResponse2.redirect(new URL(routeConfig.redirectTo || "/login", req.url));
    }
    try {
      if (routeConfig.credentials) {
        const condition = new Function("user", `return ${routeConfig.credentials}`);
        if (!session.success || !condition(session.user)) {
          return NextResponse2.redirect(new URL(routeConfig.redirectTo || "/login", req.url));
        }
      }
      return NextResponse2.next();
    } catch (error) {
      return NextResponse2.redirect(new URL(routeConfig.redirectTo || "/login", req.url));
    }
  }
  return NextResponse2.next();
}
var config2 = {
  matcher: Object.keys(routesOptions().routes).map((path2) => path2.startsWith("/") ? path2 : `/${path2}`)
};

// src/middlewere/expressMiddlewere.ts
var authMiddleware = async (req, res, next) => {
  const routes = routesOptions();
  const { originalUrl: pathname } = req;
  const cookieToken = req.cookies?.token || "";
  const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0] || req.socket.remoteAddress;
  const routeConfig = routes?.routes?.[pathname];
  if (!routeConfig) return next();
  if (routeConfig.type === "public") return next();
  if (routeConfig.type === "private") {
    if (!cookieToken) {
      return res.redirect(routeConfig.redirectTo || "/login");
    }
    try {
      const session = await getUser(cookieToken, ip);
      if (routeConfig.credentials && session.success) {
        const user = session.user;
        const condition = new Function("user", `return ${routeConfig.credentials}`);
        if (!condition(user)) {
          return res.redirect(routeConfig.redirectTo || "/login");
        }
      }
      return next();
    } catch (error) {
      console.error("Token verification error:", error);
      return res.redirect(routeConfig.redirectTo || "/login");
    }
  }
  return next();
};
var expressMiddlewere = (app) => {
  const routes = routesOptions();
  const protectedPaths = Object.keys(routes.routes);
  protectedPaths.forEach((path2) => {
    app.use(path2, authMiddleware);
  });
};

// src/hooks/userHook.tsx
import React, { createContext, useContext, useState } from "react";
var UserContext = createContext(void 0);
var UserProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  return /* @__PURE__ */ React.createElement(UserContext.Provider, { value: { user, loading, setUser, setLoading } }, children);
};
var useUser = () => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error("useUser must be used within a UserProvider");
  }
  return context;
};

// src/emailService/mailer.ts
import nodemailer from "nodemailer";
var transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});
var sendMail = async (to, subject, html, text) => {
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to,
    subject,
    html,
    text
  });
  return;
};

// src/emailService/sendVerifcationEmail.ts
var sendVerificationEmail = async (to, code) => {
  const { html, subject } = emailOptions();
  const emailHtml = html.replace(/{{code}}/g, code.toString());
  await sendMail(to, subject, emailHtml);
  return;
};

// src/auth/register.ts
import bcrypt from "bcryptjs";
async function registerUser(email, password) {
  try {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const existingUser = await users.findOne({ email });
    if (existingUser) {
      throw new Error("User already exists.");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      ...userSchemaOptions(),
      email,
      password: hashedPassword
    };
    const insertedUser = await users.insertOne(newUser);
    if (authOptions().verifcationRequired) {
      const verificationCode = await generateVerificationCode(insertedUser.insertedId.toString(), "verification");
      sendVerificationEmail(email, verificationCode);
      return { success: true, message: "User created. Verification email sent.", user: newUser };
    }
    const ip = getClientIp();
    const token = generateToken(insertedUser.insertedId.toString(), ip.toString());
    return { success: true, message: "User created.", user: newUser, token: token.hashedUserId };
  } catch (error) {
    return { success: false, message: error.message, user: {} };
  }
}

// src/auth/login.ts
import bcrypt2 from "bcryptjs";
async function loginUser(identifier, password) {
  try {
    const db = await connectToDatabase();
    const users = db.collection("users");
    const options = authOptions();
    const hashedPassword = await bcrypt2.hash(password, 10);
    let query = {};
    if (options.authMethod === "email") {
      query = { email: identifier };
    } else if (options.authMethod === "username") {
      query = { username: identifier };
    } else if (options.authMethod === "both") {
      query = { $or: [{ email: identifier }, { username: identifier }] };
    }
    const user = await users.findOne(query);
    if (!user || !await bcrypt2.compare(hashedPassword, user.password)) {
      throw new Error("Invalid credentials.");
    }
    if (options.verifcationRequired && !user.verified) {
      throw new Error("Email verification required.");
    }
    const clientIp = getClientIp();
    if (!clientIp) {
      throw new Error("Could not get client IP.");
    }
    const token = generateToken(user._id.toString(), clientIp.toString());
    await users.updateOne({ _id: user._id }, { $set: { "codes.token": token.token } });
    return { success: true, message: "User logged in.", token: token.hashedUserId, user };
  } catch (error) {
    return { success: false, message: error.message, token: "" };
  }
}

// src/auth/verification.ts
import bcrypt3 from "bcryptjs";
var verifyEmail = async (email, verificationCode) => {
  const db = await connectToDatabase();
  const users = db.collection("users");
  const user = await users.findOne({ email });
  if (!user || user.codes.verification !== verificationCode) {
    throw new Error("User not found, or verification code does not match.");
  }
  await users.updateOne(
    { email },
    {
      $set: {
        verified: true,
        "codes.verification": null
      }
    }
  );
  return { success: true, message: "Email verified." };
};
var resendVerificationEmail = async (email) => {
  const db = await connectToDatabase();
  const users = db.collection("users");
  const user = await users.findOne({ email });
  if (!user) {
    throw new Error("User not found.");
  }
  const verificationCode = await generateVerificationCode(user._id.toString(), "verification");
  await sendVerificationEmail(email, verificationCode);
  return { success: true, message: "Verification email sent." };
};
var requestPasswordReset = async (email) => {
  const db = await connectToDatabase();
  const users = db.collection("users");
  const user = await users.findOne({ email });
  if (!user) {
    throw new Error("User not found.");
  }
  const resetCode = await generateVerificationCode(user._id.toString(), "reset");
  await sendVerificationEmail(email, resetCode);
  return { success: true, message: "Password reset email sent." };
};
var resetPassword = async (email, resetCode, newPassword) => {
  const db = await connectToDatabase();
  const users = db.collection("users");
  const user = await users.findOne({ email });
  if (!user || user.codes.reset !== resetCode) {
    throw new Error("User not found, or reset code does not match.");
  }
  const hashedPassword = await bcrypt3.hash(newPassword, 10);
  await users.updateOne(
    { email },
    {
      $set: {
        password: hashedPassword,
        "codes.reset": null
      }
    }
  );
  return { success: true, message: "Password reset.", user };
};
export {
  UserProvider,
  appRouterMiddleware,
  authOptions,
  connectToDatabase,
  emailOptions,
  expressMiddlewere,
  generateToken,
  generateVerificationCode,
  getUser,
  loginUser,
  pagesRouterMiddlewere,
  registerUser,
  requestPasswordReset,
  resendVerificationEmail,
  resetPassword,
  routesOptions,
  sendMail,
  sendVerificationEmail,
  useUser,
  userSchemaOptions,
  validateToken,
  verifyEmail
};
//# sourceMappingURL=index.mjs.map
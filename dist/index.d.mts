import * as mongodb from 'mongodb';
import { Db } from 'mongodb';
import { NextRequest, NextResponse } from 'next/server';
import { Express } from 'express';
import React from 'react';
import * as bson from 'bson';

declare const connectToDatabase: () => Promise<Db>;

declare function generateToken(userId: string, clientIp: string): {
    token: string;
    hashedUserId: string;
    hashedClientIp: string;
};
declare function validateToken(token: string, userId: string, clientIp?: string | Promise<string | null>): boolean;

interface emailTemplate {
    html: string;
    subject: string;
}
interface Routes {
    routes: {
        [key: string]: {
            type: string;
            credentials?: string;
            redirectTo?: string;
        };
    };
}
declare const emailOptions: () => emailTemplate;
declare const userSchemaOptions: () => any;
declare const authOptions: () => any;
declare const routesOptions: () => Routes | null;

declare const generateVerificationCode: (userId: string, verificationMethod: string) => Promise<number>;

declare const User: any;
type User = ReturnType<typeof User>;

declare function appRouterMiddleware(req: NextRequest): Promise<NextResponse<unknown>>;

declare function pagesRouterMiddlewere(req: NextRequest): Promise<NextResponse<unknown>>;

declare const expressMiddlewere: (app: Express) => void;

interface UserContextType {
    user: User | null;
    loading: boolean;
    setUser: React.Dispatch<React.SetStateAction<User | null>>;
    setLoading: React.Dispatch<React.SetStateAction<boolean>>;
}
declare const UserProvider: React.FC<{
    children: React.ReactNode;
}>;
declare const useUser: () => UserContextType;

declare const sendMail: (to: string, subject: string, html?: string, text?: string) => Promise<void>;

declare const sendVerificationEmail: (to: string, code: number) => Promise<void>;

declare function registerUser(email: string, password: string): Promise<{
    success: boolean;
    message: string;
    user: any;
    token?: undefined;
} | {
    success: boolean;
    message: string;
    user: any;
    token: string;
} | {
    success: boolean;
    message: any;
    user: {};
    token?: undefined;
}>;

declare function loginUser(identifier: string, password: string): Promise<{
    success: boolean;
    message: string;
    token: string;
    user: mongodb.WithId<bson.Document>;
} | {
    success: boolean;
    message: any;
    token: string;
    user?: undefined;
}>;

declare const getUser: (token: string, ip?: string | null) => Promise<{
    success: boolean;
    user: mongodb.WithId<bson.Document>;
}>;

declare const verifyEmail: (email: string, verificationCode: number) => Promise<{
    success: boolean;
    message: string;
}>;
declare const resendVerificationEmail: (email: string) => Promise<{
    success: boolean;
    message: string;
}>;
declare const requestPasswordReset: (email: string) => Promise<{
    success: boolean;
    message: string;
}>;
declare const resetPassword: (email: string, resetCode: number, newPassword: string) => Promise<{
    success: boolean;
    message: string;
    user: mongodb.WithId<bson.Document>;
}>;

export { User, UserProvider, appRouterMiddleware, authOptions, connectToDatabase, emailOptions, expressMiddlewere, generateToken, generateVerificationCode, getUser, loginUser, pagesRouterMiddlewere, registerUser, requestPasswordReset, resendVerificationEmail, resetPassword, routesOptions, sendMail, sendVerificationEmail, useUser, userSchemaOptions, validateToken, verifyEmail };

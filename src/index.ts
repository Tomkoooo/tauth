// index.ts

//db

//MongoDB connection
export {connectToDatabase} from './db/mongodb';

//utils

//generateToken(userId: string, clientIp: string)
export {generateToken} from './utils/generateToken';
//validateToken(token:string, clientIp?: string)
export {validateToken} from './utils/generateToken';

//emailOptions() -> {html: string, subject: string} (auth.options.json)
export {emailOptions} from './utils/options';
//authOptions() -> {authMethod: string, verificationRequired: boolean} (auth.options.json)
export {authOptions} from './utils/options';
//userSchemaOptions() -> type User (auth.schema.json)
export {userSchemaOptions} from './utils/options';
//routesOptions() -> {routes: {key: {type: string, credentials?: string, redirectTo?: string}}} (auth.options.json)
export {routesOptions} from './utils/options';

//generateVerificationCode(userId: string, verificationMethod: string)
export {generateVerificationCode} from './utils/otp';

//types

//User type
export {User} from './types/user';

//middlewere

//appRouterMiddlewere()
export {appRouterMiddleware} from './middlewere/appRouterMidlewere';
//pagesRouterMiddlewere()
export {pagesRouterMiddlewere} from './middlewere/pagesRouterMidllewere';
//expressJS middlewere
export {expressMiddlewere} from './middlewere/expressMiddlewere';

//hooks

//userHook
export {UserProvider, useUser} from './hooks/userHook';

//emailService

//sendMail(to. string, subject: string, html?: string, text?: string)
export {sendMail} from './emailService/mailer';
//sendVerificationEmail(to: string, code: number)
export {sendVerificationEmail} from './emailService/sendVerifcationEmail';

//auth

//registerUser(email: string, password: string)
export {registerUser} from './auth/register';
//loginUser(identifier: string, password: string)
export {loginUser} from './auth/login';
//getUser(token: string, ip?: string)
export {getUser} from './auth/getUser';

//verification

//verifyEmail(token: string, verificationCode: number)
export {verifyEmail} from './auth/verification';
//resetPassword(email: string, resetCode: number, newPassword: string)
export {resetPassword} from './auth/verification';
//requestPasswordReset(email: string)
export {requestPasswordReset} from './auth/verification';
//resendVerificationEmail(email: string)
export {resendVerificationEmail} from './auth/verification';
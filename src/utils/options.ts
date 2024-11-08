// /src/utils/options.ts
'use server'
import fs from 'fs';
import path from 'path';

interface emailTemplate{
    html: string
    subject: string
}

interface Routes {
    routes: {
        [key: string]: {
            type: string
            credentials?: string
            redirectTo?: string
        }
    }
}

export const emailOptions = () => {
    const defaultEmailTemplate = {
        html: 'Please use the following code to verify your email: <strong>{{code}}</strong>',
        subject: 'Email verification code'
    }
    const optionsPath = path.resolve(process.cwd(), 'auth.options.json');
    if (!fs.existsSync(optionsPath)) {
        return defaultEmailTemplate as emailTemplate;
    }
    const options = fs.readFileSync(optionsPath, 'utf-8');
    //extract the emailTemplate object from the file
    return JSON.parse(options).emailTemplate as emailTemplate;
}
export const userSchemaOptions = () => {
    const defaultUserSchema = {
        name: '',
        email: '',
        password: '',
        role: 'user',
        verified: false,
        codes: {
          reset: null,
          token: null,
          verification: null
        }
      };
    const optionsPath = path.resolve(process.cwd(), 'auth.schema.json');
    if (!fs.existsSync(optionsPath)) {
        return defaultUserSchema;
    }
    const options = fs.readFileSync(optionsPath, 'utf-8');
    //extract the userSchema object from the file and mix it with the defaultUserSchema
    return {...defaultUserSchema, ...JSON.parse(options).userSchema};
}

export const authOptions = () => {
    const defaultOptions = {
        verifcationRequired: false,
        authMethod: 'both',
    }
    const optionsPath = path.resolve(process.cwd(), 'auth.options.json');
    if (!fs.existsSync(optionsPath)) {
        return defaultOptions;
    }
    const options = fs.readFileSync(optionsPath, 'utf-8');
    //extract the authOptions object from the file
    return JSON.parse(options).authOptions;
}

export const routesOptions = () => {
    const routeOptionsPath = path.resolve(process.cwd(), 'auth.routes.json');
    if (!fs.existsSync(routeOptionsPath)) {
        return null;
    }
    const routeOptions = fs.readFileSync(routeOptionsPath, 'utf-8');
    //extract the routes object from the file
    return JSON.parse(routeOptions) as Routes;
}
import fs from 'fs';
import path from 'path';

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

export function loadExtendedSchema() {
  const schemaPath = path.resolve(process.cwd(), 'auth.schema.json');
  if (fs.existsSync(schemaPath)) {
    const extendedSchema = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
    return { ...defaultUserSchema, ...extendedSchema };
  }
  return defaultUserSchema;
}

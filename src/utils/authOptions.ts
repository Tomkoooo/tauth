import fs from 'fs';
import path from 'path';

export function loadAuthOptions() {
    const optionsPath = path.resolve(process.cwd(), 'auth.options.json');
    if (fs.existsSync(optionsPath)) {
      return JSON.parse(fs.readFileSync(optionsPath, 'utf-8'));
    }
    return { requireEmailVerification: false, passwordReset: false };
  }

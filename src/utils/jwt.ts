// src/utils/jwt.ts
import jwt, { JwtPayload } from 'jsonwebtoken';

const SECRET_KEY = process.env.JWT_SECRET || 'SECRET_KEY';

export const generateToken = (userId: string, ipHash: string): string => {
  return jwt.sign({ userId, ipHash }, SECRET_KEY, { expiresIn: '24h' });
};

export const verifyToken = (token: string, clientIp: string): boolean => {
  try {
    const decoded = jwt.verify(token, SECRET_KEY) as JwtPayload;
    const ipHash = generateIpHash(clientIp);
    return decoded.ipHash === ipHash;
  } catch {
    return false;
  }
};

export const generateIpHash = (ip: string): string => {
  return require('crypto').createHash('sha256').update(ip + process.env.SERVER_SECRET).digest('hex');
};

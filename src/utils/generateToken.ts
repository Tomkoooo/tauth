import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

export function generateToken(userId: string, clientIp: string) {
    // Hash the userId, JWT_SECRET, and clientIp to create a unique token hash
    const hashedUserId = hash(userId + JWT_SECRET);
    const hashedClientIp = hash(clientIp + JWT_SECRET);

    // Generate a JWT with the combined hash of userId and clientIp
    const token = jwt.sign(
        { hash: hash(userId + clientIp + JWT_SECRET) },
        JWT_SECRET,
        { expiresIn: EXPIRES_IN }
    );

    // Return the JWT token, hashedUserId, and original userId hash for verification
    return {
        token,
        hashedUserId,
        hashedClientIp
    };
}

// Helper function to hash values with SHA-256
function hash(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Example function to validate the token on the server side
export function validateToken(token: string, userId: string, clientIp?: string | Promise<string | null>): boolean {
    try {
        if (!clientIp) return false;
        // Decode the JWT
        const decoded = jwt.verify(token, JWT_SECRET) as { hash: string };
        
        // Recreate the hash using the same approach
        const expectedHash = hash(userId + clientIp + JWT_SECRET);
        
        // Compare the recreated hash with the one from the token
        return decoded.hash === expectedHash;
    } catch (err) {
        console.error("Token validation error:", err);
        return false;
    }
}

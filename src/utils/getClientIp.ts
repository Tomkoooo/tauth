// src/utils/getClientIp.ts
export async function getClientIp(): Promise<string | null> {
    try {
      const response = await fetch('https://api64.ipify.org?format=json');
      if (!response.ok) throw new Error('Failed to fetch IP');
      
      const data = await response.json();
      return data.ip;
    } catch (error) {
      console.error('Could not retrieve client IP:', error);
      return null; // Fallback in case of error
    }
  }
  
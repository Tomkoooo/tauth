// src/context/UserContext.tsx

import React, { createContext, useContext, useEffect, useState } from 'react';
import { User } from '../types/userSchema'; // Assuming you have the User type defined
import { getUser } from '../auth'; // If you need this for other operations

interface UserContextType {
  user: User | null;
  loading: boolean;
  setUser: React.Dispatch<React.SetStateAction<User | null>>;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export const UserProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchUser = async () => {
      const token = localStorage.getItem('token');
      try {
        const response = await fetch('/api/user', {
          method: 'GET',
          headers: {authorization: `Bearer ${token}`},
          credentials: 'include', // Ensure cookies are sent if needed
        });
        if (response.ok) {
          const fetchedUser = await response.json();
          setUser(fetchedUser);
        } else {
          setUser(null);
        }
      } catch (error) {
        console.error("Error fetching user:", error);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

  return (
    <UserContext.Provider value={{ user, loading, setUser }}>
      {children}
    </UserContext.Provider>
  );
};

export const useUser = (): UserContextType => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error("useUser must be used within a UserProvider");
  }
  return context;
};

import React, { createContext, useContext, useState, ReactNode } from 'react';

interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: string;
  isAdmin?: boolean;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  register: (userData: Omit<User, 'id'> & { password: string; confirmPassword: string }) => Promise<boolean>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      
      // If response is not OK (401, 400, etc), login failed
      if (!res.ok) {
        // Try to get error message from response
        let errorMessage = "Login failed";
        try {
          const errorData = await res.json();
          errorMessage = errorData.error || errorMessage;
        } catch (e) {
          // If we can't parse JSON, use status text
          errorMessage = `${errorMessage}: ${res.statusText}`;
        }
        console.error('Login failed:', errorMessage);
        throw new Error(errorMessage);
      }
      
      const data = await res.json();
      
      // Verify we got valid user data
      if (!data || !data.id || !data.email) {
        console.error('Invalid user data received');
        return false;
      }
      
      const loggedInUser: User = {
        id: data.id,
        firstName: data.firstName,
        lastName: data.lastName,
        email: data.email,
        dateOfBirth: data.dateOfBirth,
        isAdmin: data.isAdmin || false,
      };
      setUser(loggedInUser);
      setIsAuthenticated(true);
      return true;
    } catch (error) {
      console.error('Login error:', error);
      throw error; // Re-throw to let the calling component handle it
    }
  };

  const register = async (userData: Omit<User, 'id'> & { password: string; confirmPassword: string }): Promise<boolean> => {
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firstName: userData.firstName,
          lastName: userData.lastName,
          email: userData.email,
          dateOfBirth: userData.dateOfBirth,
          password: userData.password,
          confirmPassword: userData.confirmPassword,
        }),
      });
      
      // Check if response is OK (2xx status)
      if (!res.ok) {
        // Try to get error message from response
        let errorMessage = "Registration failed";
        try {
          const errorData = await res.json();
          errorMessage = errorData.error || errorMessage;
        } catch (e) {
          // If we can't parse JSON, use status text
          errorMessage = `${errorMessage}: ${res.statusText}`;
        }
        console.error("Registration error:", errorMessage);
        throw new Error(errorMessage);
      }
      
      const data = await res.json();
      const newUser: User = {
        id: data.id,
        firstName: data.firstName,
        lastName: data.lastName,
        email: data.email,
        dateOfBirth: data.dateOfBirth,
      };
      setUser(newUser);
      setIsAuthenticated(true);
      return true;
    } catch (error) {
      console.error("Registration error:", error);
      throw error; // Re-throw to let the calling component handle it
    }
  };

  const logout = () => {
    setUser(null);
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
import { createContext, useContext, useState, useEffect } from 'react';
import { authService } from '../services/api';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [role, setRole] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state
  useEffect(() => {
    const initAuth = async () => {
      try {
        const res = await authService.getMe();
        if (res.data?.success && res.data?.user) {
          setUser(res.data.user);
          setRole(res.data.role);
          setIsAuthenticated(true);
        } else {
          setUser(null);
          setRole(null);
          setIsAuthenticated(false);
        }
      } catch (error) {
        setIsAuthenticated(false);
        setUser(null);
        setRole(null);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (email, password) => {
    const res = await authService.login(email, password);
    const data = res.data;
    if (data.role) {
      setRole(data.role);
      setIsAuthenticated(true);
      if (data.user) {
        setUser(data.user);
      } else {
        const meRes = await authService.getMe();
        setUser(meRes.data.user);
      }
      return data;
    }
    throw new Error('Login failed');
  };

  const logout = async () => {
    try {
      await authService.logout();
    } catch(e) {
      console.error(e);
    } finally {
      setIsAuthenticated(false);
      setUser(null);
      setRole(null);
    }
  };

  const refreshUser = async () => {
    try {
      const res = await authService.getMe();
      if (res.data?.success && res.data?.user) {
        setUser(res.data.user);
        setRole(res.data.role);
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <AuthContext.Provider value={{ user, role, isAuthenticated, isLoading, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

import { createContext, useContext, useState, useEffect } from 'react';
import { authService, userService, adminService } from '../services/api';

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
        // We try to fetch the dashboard to see if we're logged in.
        // We don't know if we are admin or user initially, so we try user first, then admin if forbidden.
        // Actually, the backend might just redirect or 401. Let's try user dashboard.
        const userData = await userService.getDashboard();
        
        if (userData && userData.role) {
          setUser(userData);
          setRole(userData.role);
          setIsAuthenticated(true);
        } else {
          // Maybe admin?
          try {
            const adminData = await adminService.getDashboard();
            if (adminData && adminData.users) {
              // We are admin. The admin dashboard doesn't return full user details for the logged-in admin natively in our parser, 
              // but we can infer role='admin'.
              setUser({ role: 'admin' }); 
              setRole('admin');
              setIsAuthenticated(true);
            }
          } catch(e) {
            // Not admin either
          }
        }
      } catch (error) {
        // Not authenticated
        setIsAuthenticated(false);
        setUser(null);
        setRole(null);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (identifier, password) => {
    const res = await authService.login(identifier, password);
    const data = res.data;
    if (data.role) {
      setRole(data.role);
      setIsAuthenticated(true);
      // We don't get full user data from login, so we fetch it based on role
      if (data.role === 'admin') {
        setUser({ role: 'admin' }); // Will fully populate later if needed
      } else {
        const userData = await userService.getDashboard();
        setUser(userData);
      }
      return data; // returns { message, role, redirect }
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
    if (role === 'user') {
      const userData = await userService.getDashboard();
      setUser(userData);
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

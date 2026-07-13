import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { LoadingOverlay } from './ui/LoadingSpinner';

export function ProtectedRoute({ requiredRole }) {
  const { isAuthenticated, isLoading, role } = useAuth();

  if (isLoading) {
    return <LoadingOverlay />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && role !== requiredRole) {
    if (role === 'admin') return <Navigate to="/admin/dashboard" replace />;
    if (role === 'user') return <Navigate to="/dashboard" replace />;
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

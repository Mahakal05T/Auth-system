import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { LoadingOverlay } from './ui/LoadingSpinner';

export function ProtectedRoute({ requiredRole }) {
  const { isAuthenticated, isLoading, role } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <LoadingOverlay />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && role !== requiredRole) {
    if (role === 'admin') return <Navigate to="/admin" replace />;
    if (role === 'user') return <Navigate to="/" replace />;
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

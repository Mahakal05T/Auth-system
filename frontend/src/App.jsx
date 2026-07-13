import { Routes, Route, Navigate } from 'react-router-dom';
import { Suspense, lazy } from 'react';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoadingOverlay } from './components/ui/LoadingSpinner';

// Layouts
import AuthLayout from './layouts/AuthLayout';
import DashboardLayout from './layouts/DashboardLayout';

// Lazy loaded pages
const LoginPage = lazy(() => import('./pages/auth/LoginPage'));
const RegisterPage = lazy(() => import('./pages/auth/RegisterPage'));
const ForgotPasswordPage = lazy(() => import('./pages/auth/ForgotPasswordPage'));
const ResetPasswordPage = lazy(() => import('./pages/auth/ResetPasswordPage'));

const DashboardPage = lazy(() => import('./pages/app/DashboardPage'));
const AdminDashboardPage = lazy(() => import('./pages/admin/AdminDashboardPage'));
const ProfilePage = lazy(() => import('./pages/app/ProfilePage')); // Placeholder
const UserManagementPage = lazy(() => import('./pages/admin/UserManagementPage')); // Placeholder
const SettingsPage = lazy(() => import('./pages/app/SettingsPage')); // Placeholder

const PlaceholderPage = ({ title }) => (
  <div className="p-8 text-center">
    <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{title}</h2>
    <p className="text-gray-500 mt-2">This page is under construction.</p>
  </div>
);

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Suspense fallback={<LoadingOverlay />}>
          <Routes>
            <Route path="/" element={<Navigate to="/login" replace />} />
            
            {/* Auth Routes */}
            <Route element={<AuthLayout />}>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route path="/forgot-password" element={<ForgotPasswordPage />} />
              <Route path="/reset-password" element={<ResetPasswordPage />} />
            </Route>

            {/* Protected User Routes */}
            <Route element={<ProtectedRoute requiredRole="user" />}>
              <Route element={<DashboardLayout />}>
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/profile" element={<PlaceholderPage title="User Profile" />} />
                <Route path="/activity" element={<PlaceholderPage title="User Activity" />} />
                <Route path="/settings" element={<PlaceholderPage title="Settings" />} />
              </Route>
            </Route>

            {/* Protected Admin Routes */}
            <Route element={<ProtectedRoute requiredRole="admin" />}>
              <Route element={<DashboardLayout />}>
                <Route path="/admin/dashboard" element={<AdminDashboardPage />} />
                <Route path="/admin/users" element={<PlaceholderPage title="User Management" />} />
              </Route>
            </Route>
            
            {/* Fallback */}
            <Route path="*" element={
              <div className="min-h-screen flex flex-col items-center justify-center text-center p-4">
                <h1 className="text-6xl font-bold text-gray-900 dark:text-white">404</h1>
                <p className="text-xl text-gray-600 dark:text-gray-400 mt-2">Page Not Found</p>
                <a href="/login" className="mt-6 px-6 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-700">Go Home</a>
              </div>
            } />
          </Routes>
        </Suspense>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;

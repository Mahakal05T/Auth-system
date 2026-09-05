import { Routes, Route, Navigate, Link } from 'react-router-dom';
import { Suspense, lazy } from 'react';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { CartProvider } from './context/CartContext';
import { WishlistProvider } from './context/WishlistContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoadingOverlay } from './components/ui/LoadingSpinner';

// Layouts
import AuthLayout from './layouts/AuthLayout';
import StorefrontLayout from './layouts/StorefrontLayout';
import AdminLayout from './layouts/AdminLayout';

// Storefront Pages
const HomePage = lazy(() => import('./pages/storefront/HomePage'));
const ProductListingPage = lazy(() => import('./pages/storefront/ProductListingPage'));
const ProductDetailPage = lazy(() => import('./pages/storefront/ProductDetailPage'));
const CartPage = lazy(() => import('./pages/storefront/CartPage'));
const WishlistPage = lazy(() => import('./pages/storefront/WishlistPage'));
const CheckoutPage = lazy(() => import('./pages/storefront/CheckoutPage'));
const OrdersPage = lazy(() => import('./pages/storefront/OrdersPage'));
const OrderTrackPage = lazy(() => import('./pages/storefront/OrderTrackPage'));
const AccountPage = lazy(() => import('./pages/storefront/AccountPage'));

// Auth Pages
const LoginPage = lazy(() => import('./pages/auth/LoginPage'));
const RegisterPage = lazy(() => import('./pages/auth/RegisterPage'));
const ForgotPasswordPage = lazy(() => import('./pages/auth/ForgotPasswordPage'));
const ResetPasswordPage = lazy(() => import('./pages/auth/ResetPasswordPage'));

// Admin Pages
const AdminOverviewPage = lazy(() => import('./pages/admin/AdminOverviewPage'));
const AdminProductsPage = lazy(() => import('./pages/admin/AdminProductsPage'));
const AdminOrdersPage = lazy(() => import('./pages/admin/AdminOrdersPage'));
const AdminInventoryPage = lazy(() => import('./pages/admin/AdminInventoryPage'));
const AdminCustomersPage = lazy(() => import('./pages/admin/AdminCustomersPage'));
const AdminCouponsPage = lazy(() => import('./pages/admin/AdminCouponsPage'));
const AdminCategoriesPage = lazy(() => import('./pages/admin/AdminCategoriesPage'));
const AdminReviewsPage = lazy(() => import('./pages/admin/AdminReviewsPage'));
const AdminReturnsPage = lazy(() => import('./pages/admin/AdminReturnsPage'));
const AdminAnalyticsPage = lazy(() => import('./pages/admin/AdminAnalyticsPage'));
const AdminSettingsPage = lazy(() => import('./pages/admin/AdminSettingsPage'));

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <CartProvider>
          <WishlistProvider>
            <Suspense fallback={<LoadingOverlay />}>
              <Routes>
                {/* 1. Public & Customer Storefront Routes */}
                <Route element={<StorefrontLayout />}>
                  <Route path="/" element={<HomePage />} />
                  <Route path="/products" element={<ProductListingPage />} />
                  <Route path="/products/:id" element={<ProductDetailPage />} />
                  <Route path="/cart" element={<CartPage />} />
                  
                  {/* Customer Protected/Account Routes */}
                  <Route path="/wishlist" element={<WishlistPage />} />
                  <Route path="/checkout" element={<CheckoutPage />} />
                  <Route path="/orders" element={<OrdersPage />} />
                  <Route path="/orders/:id/track" element={<OrderTrackPage />} />
                  <Route path="/account" element={<AccountPage />} />
                </Route>

                {/* 2. Authentication Flow Routes */}
                <Route element={<AuthLayout />}>
                  <Route path="/login" element={<LoginPage />} />
                  <Route path="/register" element={<RegisterPage />} />
                  <Route path="/forgot-password" element={<ForgotPasswordPage />} />
                  <Route path="/reset-password" element={<ResetPasswordPage />} />
                </Route>

                {/* 3. Protected Admin Center Routes */}
                <Route element={<ProtectedRoute requiredRole="admin" />}>
                  <Route element={<AdminLayout />}>
                    <Route path="/admin" element={<AdminOverviewPage />} />
                    <Route path="/admin/products" element={<AdminProductsPage />} />
                    <Route path="/admin/orders" element={<AdminOrdersPage />} />
                    <Route path="/admin/inventory" element={<AdminInventoryPage />} />
                    <Route path="/admin/customers" element={<AdminCustomersPage />} />
                    <Route path="/admin/categories" element={<AdminCategoriesPage />} />
                    <Route path="/admin/coupons" element={<AdminCouponsPage />} />
                    <Route path="/admin/reviews" element={<AdminReviewsPage />} />
                    <Route path="/admin/returns" element={<AdminReturnsPage />} />
                    <Route path="/admin/analytics" element={<AdminAnalyticsPage />} />
                    <Route path="/admin/settings" element={<AdminSettingsPage />} />
                  </Route>
                </Route>

                {/* Compatibility redirects: ensure legacy paths route safely to storefront root / or admin */}
                <Route path="/dashboard" element={<Navigate to="/" replace />} />
                <Route path="/admin/dashboard" element={<Navigate to="/admin" replace />} />
                
                {/* 4. Fallback 404 Route */}
                <Route path="*" element={
                  <div className="min-h-screen flex flex-col items-center justify-center text-center p-4 bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100">
                    <h1 className="text-6xl font-black text-brand-600">404</h1>
                    <p className="text-xl font-bold mt-2">Page Not Found</p>
                    <p className="text-xs text-gray-500 mt-1 max-w-sm">
                      The page you are looking for does not exist or has been moved.
                    </p>
                    <Link to="/" className="mt-6 px-6 py-2.5 bg-brand-600 text-white rounded-full text-xs font-semibold hover:bg-brand-700 shadow-md">
                      Return to Storefront
                    </Link>
                  </div>
                } />
              </Routes>
            </Suspense>
          </WishlistProvider>
        </CartProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;

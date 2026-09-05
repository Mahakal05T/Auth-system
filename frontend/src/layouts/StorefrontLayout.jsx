import { Outlet } from 'react-router-dom';
import { StorefrontNavbar } from '../components/storefront/StorefrontNavbar';
import { StorefrontFooter } from '../components/storefront/StorefrontFooter';

export default function StorefrontLayout() {
  return (
    <div className="min-h-screen flex flex-col bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 transition-colors">
      <StorefrontNavbar />
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        <Outlet />
      </main>
      <StorefrontFooter />
    </div>
  );
}

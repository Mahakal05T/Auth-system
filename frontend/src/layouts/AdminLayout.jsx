import { useState } from 'react';
import { Outlet, NavLink, Link, useNavigate } from 'react-router-dom';
import { 
  LayoutDashboard, ShoppingBag, FolderTree, Package, ClipboardList, 
  Users, TicketPercent, Star, RotateCcw, BarChart3, Settings, 
  LogOut, Sun, Moon, Menu, X, ExternalLink, Shield
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { cn } from '../utils/helpers';

const adminNavLinks = [
  { name: 'Overview', to: '/admin', icon: LayoutDashboard, exact: true },
  { name: 'Products', to: '/admin/products', icon: ShoppingBag },
  { name: 'Categories', to: '/admin/categories', icon: FolderTree },
  { name: 'Orders', to: '/admin/orders', icon: ClipboardList },
  { name: 'Inventory', to: '/admin/inventory', icon: Package },
  { name: 'Customers', to: '/admin/customers', icon: Users },
  { name: 'Coupons', to: '/admin/coupons', icon: TicketPercent },
  { name: 'Reviews', to: '/admin/reviews', icon: Star },
  { name: 'Returns', to: '/admin/returns', icon: RotateCcw },
  { name: 'Analytics', to: '/admin/analytics', icon: BarChart3 },
  { name: 'Settings', to: '/admin/settings', icon: Settings },
];

export default function AdminLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-950 text-gray-900 dark:text-gray-100 flex flex-col transition-colors">
      {/* Admin Top Header */}
      <header className="sticky top-0 z-40 h-16 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 px-4 sm:px-6 flex items-center justify-between shadow-xs">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="lg:hidden p-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            <Menu className="w-5 h-5" />
          </button>

          <Link to="/admin" className="flex items-center gap-2 font-bold text-lg text-brand-600 dark:text-brand-400">
            <div className="w-8 h-8 rounded-lg bg-brand-600 text-white flex items-center justify-center font-black">
              <Shield className="w-4 h-4" />
            </div>
            <span>Admin Center</span>
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/"
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 border border-gray-200 dark:border-gray-700 transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" /> View Storefront
          </Link>

          <button
            onClick={toggleTheme}
            className="p-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            title="Toggle theme"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
          </button>

          <div className="h-5 w-px bg-gray-200 dark:bg-gray-700 mx-1" />

          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-gray-700 dark:text-gray-300 hidden md:block">
              {user?.name || 'Administrator'}
            </span>
            <button
              onClick={handleLogout}
              className="p-2 rounded-lg text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex flex-1 max-w-[1600px] w-full mx-auto">
        {/* Mobile Backdrop */}
        {isSidebarOpen && (
          <div
            className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-xs"
            onClick={() => setIsSidebarOpen(false)}
          />
        )}

        {/* Admin Sidebar Navigation */}
        <aside
          className={cn(
            "fixed lg:sticky top-16 left-0 z-50 h-[calc(100vh-4rem)] w-60 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col justify-between p-3 transition-transform duration-200 shrink-0",
            isSidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
          )}
        >
          <div className="flex items-center justify-between p-2 lg:hidden border-b border-gray-100 dark:border-gray-800 mb-2">
            <span className="font-bold text-xs uppercase tracking-wider text-gray-400">Navigation</span>
            <button onClick={() => setIsSidebarOpen(false)} className="p-1 text-gray-400">
              <X className="w-4 h-4" />
            </button>
          </div>

          <nav className="space-y-1 overflow-y-auto pr-1">
            {adminNavLinks.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.exact}
                onClick={() => setIsSidebarOpen(false)}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium transition-colors",
                    isActive
                      ? "bg-brand-600 text-white shadow-xs"
                      : "text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
                  )
                }
              >
                <item.icon className="w-4 h-4 shrink-0" />
                <span>{item.name}</span>
              </NavLink>
            ))}
          </nav>

          <div className="pt-3 border-t border-gray-100 dark:border-gray-800">
            <div className="px-3 py-2 rounded-xl bg-gray-50 dark:bg-gray-800/60 text-[11px] text-gray-500 dark:text-gray-400">
              <div className="font-bold text-gray-800 dark:text-gray-200">ApexStore Admin</div>
              <div>System Version 2.0</div>
            </div>
          </div>
        </aside>

        {/* Admin Content Area */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 min-w-0 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

import { Menu, LogOut, Sun, Moon } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { Avatar } from '../ui/Avatar';
import { Link, useNavigate } from 'react-router-dom';

export function Navbar({ onMenuClick }) {
  const { user, role, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <nav className="fixed top-0 w-full bg-white/80 dark:bg-gray-900/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-800 z-30 transition-colors">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 lg:h-16">
          <div className="flex items-center gap-3">
            <button 
              onClick={onMenuClick}
              className="p-2 -ml-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 lg:hidden focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <Menu className="w-6 h-6" />
            </button>
            <Link to={role === 'admin' ? '/admin/dashboard' : '/dashboard'} className="flex items-center gap-2 focus:outline-none focus:ring-2 focus:ring-brand-500 rounded-lg">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center shadow-sm">
                <span className="text-white font-bold text-xl leading-none font-sans">A</span>
              </div>
              <span className="font-semibold text-lg tracking-tight hidden sm:block text-gray-900 dark:text-white">AuthSystem</span>
            </Link>
          </div>

          <div className="flex items-center gap-2 sm:gap-4">
            <button
              onClick={toggleTheme}
              className="p-2 rounded-full text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800 transition-colors focus:outline-none focus:ring-2 focus:ring-brand-500"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            
            <div className="h-6 w-px bg-gray-200 dark:bg-gray-700 hidden sm:block" />

            {user && (
              <div className="flex items-center gap-3">
                <div className="hidden sm:flex flex-col items-end">
                  <span className="text-sm font-medium text-gray-900 dark:text-white">{user.name || 'Administrator'}</span>
                  <span className="text-xs text-gray-500 dark:text-gray-400 capitalize">{role}</span>
                </div>
                <Avatar name={user.name} size="sm" />
                <button
                  onClick={handleLogout}
                  className="p-2 rounded-full text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors ml-1 focus:outline-none focus:ring-2 focus:ring-red-500"
                  title="Logout"
                >
                  <LogOut className="w-5 h-5" />
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

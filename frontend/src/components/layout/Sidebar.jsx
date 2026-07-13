import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Users, UserCircle, Settings, Activity, X } from 'lucide-react';
import { cn } from '../../utils/helpers';

const userLinks = [
  { name: 'Dashboard', to: '/dashboard', icon: LayoutDashboard },
  { name: 'Profile', to: '/profile', icon: UserCircle },
  { name: 'Activity', to: '/activity', icon: Activity },
  { name: 'Settings', to: '/settings', icon: Settings },
];

const adminLinks = [
  { name: 'Dashboard', to: '/admin/dashboard', icon: LayoutDashboard },
  { name: 'User Management', to: '/admin/users', icon: Users },
  { name: 'Settings', to: '/settings', icon: Settings },
];

export function Sidebar({ isOpen, onClose, role }) {
  const links = role === 'admin' ? adminLinks : userLinks;

  return (
    <aside className={cn(
      "fixed lg:sticky top-0 lg:top-16 left-0 z-50 h-screen lg:h-[calc(100vh-4rem)] w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 transition-transform duration-300 ease-in-out transform shrink-0",
      isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
    )}>
      <div className="flex items-center justify-between p-4 lg:hidden border-b border-gray-200 dark:border-gray-800">
        <span className="font-semibold text-lg text-gray-900 dark:text-white">Menu</span>
        <button onClick={onClose} className="p-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-brand-500">
          <X className="w-5 h-5" />
        </button>
      </div>

      <nav className="p-4 space-y-1">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            onClick={() => {
              if (window.innerWidth < 1024) onClose();
            }}
            className={({ isActive }) => cn(
              "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-500",
              isActive 
                ? "bg-brand-50 text-brand-700 dark:bg-brand-500/10 dark:text-brand-400" 
                : "text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800/50"
            )}
          >
            <link.icon className="w-5 h-5" />
            {link.name}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

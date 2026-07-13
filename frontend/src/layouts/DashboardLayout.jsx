import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Navbar } from '../components/layout/Navbar';
import { Sidebar } from '../components/layout/Sidebar';
import { useAuth } from '../context/AuthContext';

export default function DashboardLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { role } = useAuth();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 transition-colors text-gray-900 dark:text-gray-100">
      <Navbar onMenuClick={() => setIsSidebarOpen(true)} />
      
      <div className="flex max-w-[1600px] mx-auto">
        {isSidebarOpen && (
          <div 
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 lg:hidden"
            onClick={() => setIsSidebarOpen(false)}
          />
        )}
        
        <Sidebar 
          isOpen={isSidebarOpen} 
          onClose={() => setIsSidebarOpen(false)} 
          role={role}
        />
        
        <main className="flex-1 p-4 sm:p-6 lg:p-8 w-full max-w-full overflow-x-hidden pt-20 lg:pt-24 min-h-screen">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

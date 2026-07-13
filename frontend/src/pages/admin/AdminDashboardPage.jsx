import { useEffect, useState } from 'react';
import { adminService } from '../../services/api';
import { CardSkeleton, TableSkeleton } from '../../components/ui/SkeletonLoader';
import { Users, UserCheck } from 'lucide-react';
import { RoleBadge } from '../../components/ui/RoleBadge';

export default function AdminDashboardPage() {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchAdminData = async () => {
      try {
        const res = await adminService.getDashboard();
        setData(res);
      } catch(e) {
        console.error(e);
      } finally {
        setIsLoading(false);
      }
    };
    fetchAdminData();
  }, []);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Admin Dashboard</h1>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <CardSkeleton />
          <CardSkeleton />
        </div>
        <div className="glass-card rounded-2xl p-6">
          <TableSkeleton rows={5} />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header>
        <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Admin Dashboard</h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">Overview of the system</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="glass-card rounded-2xl p-6 flex items-center gap-4 border-l-4 border-brand-500">
          <div className="p-3 bg-brand-100 dark:bg-brand-900/30 text-brand-600 dark:text-brand-400 rounded-xl">
            <Users size={24} />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Users</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{data?.stats?.total_users || 0}</p>
          </div>
        </div>

        <div className="glass-card rounded-2xl p-6 flex items-center gap-4 border-l-4 border-green-500">
          <div className="p-3 bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 rounded-xl">
            <UserCheck size={24} />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Users</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{data?.stats?.active_users || 0}</p>
          </div>
        </div>
      </div>

      <div className="glass-card rounded-2xl overflow-hidden border border-gray-200 dark:border-gray-800 shadow-sm">
        <div className="p-6 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center">
          <h2 className="text-lg font-bold text-gray-900 dark:text-white">Recent Users</h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[600px]">
            <thead>
              <tr className="bg-gray-50 dark:bg-gray-800/50 border-b border-gray-200 dark:border-gray-800 text-xs uppercase font-semibold text-gray-500 dark:text-gray-400">
                <th className="px-6 py-4">Employee</th>
                <th className="px-6 py-4">Contact</th>
                <th className="px-6 py-4">Department</th>
                <th className="px-6 py-4">Role</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {data?.users?.slice(0, 5).map((u, idx) => (
                <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="font-medium text-gray-900 dark:text-white">{u.name}</div>
                    <div className="text-xs font-mono text-gray-500">{u.emp_id}</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-900 dark:text-gray-300">{u.email}</div>
                    <div className="text-xs text-gray-500">{u.phone}</div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{u.department || '-'}</td>
                  <td className="px-6 py-4">
                    <RoleBadge role={u.role} />
                  </td>
                </tr>
              ))}
              {!data?.users?.length && (
                <tr>
                  <td colSpan="4" className="px-6 py-8 text-center text-gray-500">No users found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

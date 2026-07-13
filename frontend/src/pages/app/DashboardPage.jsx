import { useAuth } from '../../context/AuthContext';
import { CardSkeleton } from '../../components/ui/SkeletonLoader';
import { StatusBadge } from '../../components/ui/StatusBadge';
import { RoleBadge } from '../../components/ui/RoleBadge';

export default function DashboardPage() {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <CardSkeleton />
          <CardSkeleton />
        </div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="flex justify-between items-end">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">Welcome back, {user.name}!</p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-card rounded-2xl p-6 flex flex-col items-center text-center">
          <div className="w-24 h-24 rounded-full bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-300 flex items-center justify-center text-3xl font-bold mb-4 border border-brand-200 dark:border-brand-700">
            {user.name?.charAt(0).toUpperCase()}
          </div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">{user.name}</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">{user.email}</p>
          <div className="flex gap-2 justify-center">
            <RoleBadge role={user.role} />
            <StatusBadge status={user.status || 'active'} />
          </div>
        </div>

        <div className="md:col-span-2 glass-card rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white border-b border-gray-100 dark:border-gray-800 pb-4 mb-4">Account Information</h3>
          
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6">
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Employee ID</dt>
              <dd className="mt-1 text-base text-gray-900 dark:text-white font-mono">{user.emp_id}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Department</dt>
              <dd className="mt-1 text-base text-gray-900 dark:text-white">{user.department || 'Not Assigned'}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Phone</dt>
              <dd className="mt-1 text-base text-gray-900 dark:text-white">{user.phone}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Account Created</dt>
              <dd className="mt-1 text-base text-gray-900 dark:text-white">{user.created_at || 'Recently'}</dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
}

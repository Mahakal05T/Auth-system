import { cn } from "../../utils/helpers";

export function RoleBadge({ role }) {
  const isAdmin = role?.toLowerCase() === 'admin';
  
  return (
    <span className={cn(
      "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize",
      isAdmin 
        ? "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300 border border-purple-200 dark:border-purple-800/50" 
        : "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border border-blue-200 dark:border-blue-800/50"
    )}>
      {role || 'User'}
    </span>
  );
}

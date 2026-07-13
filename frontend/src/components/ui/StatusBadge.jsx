import { cn } from "../../utils/helpers";

export function StatusBadge({ status }) {
  const isActive = status?.toLowerCase() === 'active';
  
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium",
      isActive 
        ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300 border border-green-200 dark:border-green-800/50" 
        : "bg-gray-100 text-gray-800 dark:bg-gray-800/50 dark:text-gray-300 border border-gray-200 dark:border-gray-700/50"
    )}>
      <span className={cn("w-1.5 h-1.5 rounded-full", isActive ? "bg-green-500" : "bg-gray-500")} />
      {isActive ? 'Active' : 'Inactive'}
    </span>
  );
}

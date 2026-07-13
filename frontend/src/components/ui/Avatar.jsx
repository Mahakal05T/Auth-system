import { cn } from "../../utils/helpers";

export function Avatar({ name, size = "md", className }) {
  const initial = name ? name.charAt(0).toUpperCase() : "U";
  
  const sizeClasses = {
    sm: "w-8 h-8 text-sm",
    md: "w-10 h-10 text-base",
    lg: "w-16 h-16 text-2xl"
  };

  return (
    <div className={cn(
      "rounded-full flex items-center justify-center font-bold text-brand-700 dark:text-brand-300 shrink-0",
      "bg-gradient-to-br from-brand-50 to-brand-100 dark:from-brand-900/40 dark:to-brand-800/20 border border-brand-200 dark:border-brand-700/50",
      sizeClasses[size],
      className
    )}>
      {initial}
    </div>
  );
}

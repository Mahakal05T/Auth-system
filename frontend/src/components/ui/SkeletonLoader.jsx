import { cn } from "../../utils/helpers";

export function SkeletonLoader({ className }) {
  return (
    <div className={cn("animate-pulse bg-gray-200 dark:bg-gray-800 rounded-md", className)} />
  );
}

export function CardSkeleton() {
  return (
    <div className="p-6 glass-card rounded-2xl space-y-4">
      <SkeletonLoader className="h-6 w-1/3 mb-4" />
      <SkeletonLoader className="h-4 w-full" />
      <SkeletonLoader className="h-4 w-5/6" />
      <SkeletonLoader className="h-4 w-4/6" />
    </div>
  );
}

export function TableSkeleton({ rows = 5 }) {
  return (
    <div className="w-full space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 p-4 border border-gray-100 dark:border-gray-800 rounded-xl">
          <SkeletonLoader className="h-6 w-12" />
          <SkeletonLoader className="h-6 w-1/4" />
          <SkeletonLoader className="h-6 w-1/4" />
          <SkeletonLoader className="h-6 w-1/6 ml-auto" />
        </div>
      ))}
    </div>
  );
}

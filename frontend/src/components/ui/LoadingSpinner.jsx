import { Loader2 } from "lucide-react";
import { cn } from "../../utils/helpers";

export function LoadingSpinner({ className }) {
  return (
    <Loader2 className={cn("animate-spin text-brand-500", className || "w-6 h-6")} />
  );
}

export function LoadingOverlay() {
  return (
    <div className="fixed inset-0 bg-black/20 dark:bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-2xl flex flex-col items-center gap-3">
        <LoadingSpinner className="w-10 h-10" />
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Processing...</span>
      </div>
    </div>
  );
}

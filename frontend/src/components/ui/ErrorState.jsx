import { AlertCircle } from "lucide-react";

export function ErrorState({ title = "Something went wrong", message, onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center bg-red-50 dark:bg-red-900/10 rounded-2xl border border-red-100 dark:border-red-900/30">
      <AlertCircle className="w-12 h-12 text-red-500 mb-4" />
      <h3 className="text-lg font-medium text-red-800 dark:text-red-400 mb-2">{title}</h3>
      {message && <p className="text-sm text-red-600 dark:text-red-300 max-w-sm mb-6">{message}</p>}
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-4 py-2 bg-white dark:bg-gray-800 text-red-600 dark:text-red-400 text-sm font-medium rounded-lg border border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
        >
          Try Again
        </button>
      )}
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Search } from 'lucide-react';

export function SearchBar({ value, onChange, placeholder = "Search...", className = "" }) {
  const [searchTerm, setSearchTerm] = useState(value || "");

  useEffect(() => {
    const timer = setTimeout(() => {
      onChange(searchTerm);
    }, 300); // 300ms debounce

    return () => clearTimeout(timer);
  }, [searchTerm, onChange]);

  // Update local state if prop changes externally
  useEffect(() => {
    setSearchTerm(value || "");
  }, [value]);

  return (
    <div className={`relative ${className}`}>
      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <Search className="h-5 w-5 text-gray-400" />
      </div>
      <input
        type="text"
        className="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg leading-5 bg-white dark:bg-gray-900 text-gray-900 dark:text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 sm:text-sm transition-colors"
        placeholder={placeholder}
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />
    </div>
  );
}

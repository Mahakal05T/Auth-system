import { useEffect, useState } from 'react';
import { cn } from '../../utils/helpers';

export function PasswordStrength({ password = "" }) {
  const [strength, setStrength] = useState(0);

  useEffect(() => {
    let score = 0;
    if (!password) {
      setStrength(0);
      return;
    }

    if (password.length >= 8) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    setStrength(score);
  }, [password]);

  const bars = Array.from({ length: 5 });
  
  const getStrengthColor = (index, strength) => {
    if (index >= strength) return "bg-gray-200 dark:bg-gray-800";
    if (strength <= 2) return "bg-red-500";
    if (strength === 3 || strength === 4) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getStrengthText = (strength) => {
    if (strength === 0) return "";
    if (strength <= 2) return "Weak";
    if (strength <= 4) return "Good";
    return "Strong";
  };

  return (
    <div className="w-full space-y-1 mt-2">
      <div className="flex gap-1 h-1.5">
        {bars.map((_, i) => (
          <div
            key={i}
            className={cn(
              "flex-1 rounded-full transition-colors duration-300",
              getStrengthColor(i, strength)
            )}
          />
        ))}
      </div>
      <p className="text-xs text-right text-gray-500 h-4">
        {getStrengthText(strength)}
      </p>
    </div>
  );
}

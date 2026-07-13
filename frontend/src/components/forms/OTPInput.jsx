import { useState, useRef, useEffect } from 'react';
import { cn } from '../../utils/helpers';

export function OTPInput({ length = 6, value = "", onChange, className }) {
  const [otp, setOtp] = useState(new Array(length).fill(""));
  const inputRefs = useRef([]);

  useEffect(() => {
    if (value && value.length <= length) {
      const valueArr = value.split("");
      const newOtp = [...otp];
      valueArr.forEach((char, index) => {
        newOtp[index] = char;
      });
      setOtp(newOtp);
    }
  }, [value, length]);

  const handleChange = (element, index) => {
    const val = element.value;
    if (isNaN(val)) return false;

    const newOtp = [...otp];
    newOtp[index] = val;
    setOtp(newOtp);
    
    onChange(newOtp.join(""));

    // Focus next input
    if (val !== "" && index < length - 1) {
      inputRefs.current[index + 1].focus();
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Backspace" && !otp[index] && index > 0) {
      // Focus previous input on backspace if current is empty
      inputRefs.current[index - 1].focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData("text/plain").slice(0, length);
    if (!/^\d+$/.test(pastedData)) return;

    const newOtp = [...otp];
    pastedData.split("").forEach((char, index) => {
      newOtp[index] = char;
    });
    setOtp(newOtp);
    onChange(newOtp.join(""));

    // Focus the next empty input or the last one
    const nextIndex = Math.min(pastedData.length, length - 1);
    inputRefs.current[nextIndex].focus();
  };

  return (
    <div className={cn("flex items-center justify-between gap-2", className)} onPaste={handlePaste}>
      {otp.map((data, index) => (
        <input
          key={index}
          type="text"
          inputMode="numeric"
          maxLength={1}
          ref={(ref) => (inputRefs.current[index] = ref)}
          value={data}
          onChange={(e) => handleChange(e.target, index)}
          onKeyDown={(e) => handleKeyDown(e, index)}
          className={cn(
            "w-10 sm:w-12 h-12 sm:h-14 text-center text-xl font-semibold bg-white dark:bg-gray-900 border rounded-xl",
            "focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-brand-500 transition-all",
            data 
              ? "border-brand-500 dark:border-brand-500 text-brand-700 dark:text-brand-400" 
              : "border-gray-300 dark:border-gray-700 text-gray-900 dark:text-gray-100"
          )}
        />
      ))}
    </div>
  );
}

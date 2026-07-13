import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { authService } from '../../services/api';
import { OTPInput } from '../../components/forms/OTPInput';

export default function ForgotPasswordPage() {
  const [step, setStep] = useState(1);
  const [identifier, setIdentifier] = useState('');
  const [otp, setOtp] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    let timer;
    if (countdown > 0) {
      timer = setInterval(() => setCountdown(c => c - 1), 1000);
    }
    return () => clearInterval(timer);
  }, [countdown]);

  const handleSendOtp = async (e) => {
    e?.preventDefault();
    if (!identifier) {
      toast.error('Enter Employee ID or Email');
      return;
    }

    setIsLoading(true);
    try {
      const res = await authService.forgotPassword(identifier);
      toast.success(res.data.message || 'OTP Sent');
      setStep(2);
      setCountdown(30);
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to send OTP');
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e?.preventDefault();
    if (otp.length < 6) {
      toast.error('Enter the full OTP');
      return;
    }

    setIsLoading(true);
    try {
      const res = await authService.forgotPassword(identifier, otp);
      toast.success('OTP verified! Check email for reset link.');
      setTimeout(() => navigate('/login'), 3000);
    } catch (error) {
      toast.error(error.response?.data?.error || 'Invalid OTP');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="glass-card rounded-3xl p-6 sm:p-8 space-y-6">
      <Link to="/login" className="inline-flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
        <ArrowLeft size={16} /> Back to Login
      </Link>

      <div className="text-center">
        <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Forgot Password</h2>
        <p className="text-gray-500 dark:text-gray-300 mt-2">
          {step === 1 ? 'Enter your details to receive an OTP' : 'Enter the OTP sent to your email'}
        </p>
      </div>

      {step === 1 ? (
        <form onSubmit={handleSendOtp} className="space-y-4">
          <input 
            type="text"
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
            placeholder="Employee ID or Email" 
            className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
            required
          />
          <button 
            type="submit" 
            disabled={isLoading}
            className="w-full bg-brand-600 hover:bg-brand-700 text-white font-semibold py-3 rounded-lg shadow-lg shadow-brand-500/30 transition-all flex justify-center items-center gap-2 disabled:opacity-70"
          >
            {isLoading && <Loader2 className="w-5 h-5 animate-spin" />}
            Send OTP
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerifyOtp} className="space-y-6">
          <div className="flex justify-center">
            <OTPInput length={6} value={otp} onChange={setOtp} />
          </div>
          
          <button 
            type="submit" 
            disabled={isLoading}
            className="w-full bg-green-600 hover:bg-green-700 text-white font-semibold py-3 rounded-lg shadow-lg shadow-green-500/30 transition-all flex justify-center items-center gap-2 disabled:opacity-70"
          >
            {isLoading && <Loader2 className="w-5 h-5 animate-spin" />}
            Verify OTP
          </button>

          <p className="text-center text-sm text-gray-500 dark:text-gray-400">
            {countdown > 0 ? (
              <span>Resend code in <span className="font-medium text-gray-900 dark:text-white">{countdown}s</span></span>
            ) : (
              <button 
                type="button" 
                onClick={handleSendOtp} 
                className="text-brand-600 dark:text-brand-400 hover:underline"
              >
                Resend Code
              </button>
            )}
          </p>
        </form>
      )}
    </div>
  );
}

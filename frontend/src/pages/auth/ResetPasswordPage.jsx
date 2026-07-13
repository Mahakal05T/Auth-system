import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useNavigate, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Eye, EyeOff, Loader2 } from 'lucide-react';
import { resetPasswordSchema } from '../../utils/validation';
import { authService } from '../../services/api';
import { PasswordStrength } from '../../components/forms/PasswordStrength';

export default function ResetPasswordPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } = useForm({
    resolver: zodResolver(resetPasswordSchema)
  });

  const passwordValue = watch('newPassword', '');

  const onSubmit = async (data) => {
    if (!token) {
      toast.error('Reset token is missing from URL');
      return;
    }

    try {
      const res = await authService.resetPassword(token, data.newPassword);
      toast.success(res.data.message || 'Password reset successfully');
      setTimeout(() => navigate('/login'), 1500);
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to reset password');
    }
  };

  return (
    <div className="glass-card rounded-3xl p-6 sm:p-8 space-y-6">
      <div className="text-center">
        <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Reset Password</h2>
        <p className="text-gray-500 dark:text-gray-300 mt-2">Create a new strong password</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <div className="relative">
            <input 
              {...register('newPassword')}
              type={showPassword ? 'text' : 'password'}
              placeholder="New Password" 
              className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
            />
            <button 
              type="button" 
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-3 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white"
            >
              {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
            </button>
          </div>
          <PasswordStrength password={passwordValue} />
          {errors.newPassword && <p className="text-red-500 text-sm mt-1">{errors.newPassword.message}</p>}
        </div>

        <div>
          <div className="relative">
            <input 
              {...register('confirmPassword')}
              type={showConfirmPassword ? 'text' : 'password'}
              placeholder="Confirm New Password" 
              className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
            />
            <button 
              type="button" 
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              className="absolute right-3 top-3 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white"
            >
              {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
            </button>
          </div>
          {errors.confirmPassword && <p className="text-red-500 text-sm mt-1">{errors.confirmPassword.message}</p>}
        </div>

        <button 
          type="submit" 
          disabled={isSubmitting}
          className="w-full bg-green-600 hover:bg-green-700 text-white font-semibold py-3 rounded-lg shadow-lg shadow-green-500/30 transition-all flex justify-center items-center gap-2 disabled:opacity-70 mt-4"
        >
          {isSubmitting && <Loader2 className="w-5 h-5 animate-spin" />}
          Update Password
        </button>
      </form>
    </div>
  );
}

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Eye, EyeOff, Loader2 } from 'lucide-react';
import { registerSchema } from '../../utils/validation';
import { authService } from '../../services/api';
import { PasswordStrength } from '../../components/forms/PasswordStrength';

export default function RegisterPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const navigate = useNavigate();

  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } = useForm({
    resolver: zodResolver(registerSchema)
  });

  const passwordValue = watch('password', '');

  const onSubmit = async (data) => {
    try {
      const res = await authService.register(data);
      toast.success(res.data.message || 'Registration successful');
      setTimeout(() => navigate('/login'), 1500);
    } catch (error) {
      toast.error(error.response?.data?.error || 'Registration failed');
    }
  };

  return (
    <div className="glass-card rounded-3xl p-6 sm:p-8 space-y-6">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Create Account</h2>
        <p className="text-gray-500 dark:text-gray-300 mt-1">Sign up to get started</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <input 
            {...register('name')}
            placeholder="Full Name" 
            className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
          />
          {errors.name && <p className="text-red-500 text-sm mt-1">{errors.name.message}</p>}
        </div>

        <div>
          <input 
            {...register('email')}
            placeholder="Email Address" 
            className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
          />
          {errors.email && <p className="text-red-500 text-sm mt-1">{errors.email.message}</p>}
        </div>

        <div>
          <input 
            {...register('phone')}
            placeholder="Phone Number" 
            className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
          />
          {errors.phone && <p className="text-red-500 text-sm mt-1">{errors.phone.message}</p>}
        </div>

        <div>
          <div className="relative">
            <input 
              {...register('password')}
              type={showPassword ? 'text' : 'password'}
              placeholder="Password" 
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
          {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password.message}</p>}
        </div>

        <div>
          <div className="relative">
            <input 
              {...register('confirmPassword')}
              type={showConfirmPassword ? 'text' : 'password'}
              placeholder="Confirm Password" 
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
          className="w-full bg-brand-600 hover:bg-brand-700 text-white font-semibold py-3 rounded-lg shadow-lg shadow-brand-500/30 transition-all flex justify-center items-center gap-2 disabled:opacity-70 mt-2"
        >
          {isSubmitting && <Loader2 className="w-5 h-5 animate-spin" />}
          Sign Up
        </button>
      </form>

      <p className="text-center text-sm text-gray-600 dark:text-gray-300 mt-6">
        Already have an account? <Link to="/login" className="text-brand-600 dark:text-brand-400 font-medium hover:underline">Log in</Link>
      </p>
    </div>
  );
}

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Eye, EyeOff, Loader2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { loginSchema } from '../../utils/validation';

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm({
    resolver: zodResolver(loginSchema)
  });

  const onSubmit = async (data) => {
    try {
      const res = await login(data.identifier, data.password);
      toast.success(res.message || 'Login successful');
      
      if (res.role === 'admin') navigate('/admin/dashboard');
      else navigate('/dashboard');
      
    } catch (error) {
      toast.error(error.response?.data?.error || 'Login failed');
    }
  };

  return (
    <div className="glass-card rounded-3xl p-6 sm:p-8 space-y-6">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Welcome Back</h2>
        <p className="text-gray-500 dark:text-gray-300 mt-1">Sign in to your account</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <input 
            {...register('identifier')}
            placeholder="Employee ID or Email" 
            className="w-full bg-white/50 dark:bg-black/20 border border-gray-300 dark:border-white/20 rounded-lg px-4 py-3 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
          />
          {errors.identifier && <p className="text-red-500 text-sm mt-1">{errors.identifier.message}</p>}
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
          {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password.message}</p>}
        </div>

        <div className="flex items-center justify-between text-sm">
          <label className="flex items-center gap-2 text-gray-600 dark:text-gray-300 cursor-pointer">
            <input type="checkbox" className="w-4 h-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500" /> 
            Remember me
          </label>
          <Link to="/forgot-password" className="text-brand-600 dark:text-brand-400 hover:underline">Forgot password?</Link>
        </div>

        <button 
          type="submit" 
          disabled={isSubmitting}
          className="w-full bg-brand-600 hover:bg-brand-700 text-white font-semibold py-3 rounded-lg shadow-lg shadow-brand-500/30 transition-all flex justify-center items-center gap-2 disabled:opacity-70"
        >
          {isSubmitting && <Loader2 className="w-5 h-5 animate-spin" />}
          Login
        </button>
      </form>

      <p className="text-center text-sm text-gray-600 dark:text-gray-300 mt-6">
        Don't have an account? <Link to="/register" className="text-brand-600 dark:text-brand-400 font-medium hover:underline">Sign up</Link>
      </p>
    </div>
  );
}

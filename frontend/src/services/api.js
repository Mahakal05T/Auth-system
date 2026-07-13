import axios from 'axios';

// Connect directly to the Flask backend URL. 
// Uses VITE_API_URL if set (e.g. for production), otherwise defaults to local Flask server.
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000',
  withCredentials: true, // Crucial for cookie-based JWTs
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper to get CSRF access token from cookies
const getCsrfToken = () => {
  const match = document.cookie.match(new RegExp('(^| )csrf_access_token=([^;]+)'));
  return match ? match[2] : null;
};

// Helper to get CSRF refresh token from cookies
const getRefreshCsrfToken = () => {
  const match = document.cookie.match(new RegExp('(^| )csrf_refresh_token=([^;]+)'));
  return match ? match[2] : null;
};

// Request interceptor to attach CSRF token for mutating requests
api.interceptors.request.use((config) => {
  const method = config.method?.toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    // Determine which CSRF token to use
    const isRefreshRoute = config.url === '/token/refresh' || config.url?.includes('/token/refresh');
    const csrfToken = isRefreshRoute ? getRefreshCsrfToken() : getCsrfToken();
    
    if (csrfToken) {
      config.headers['X-CSRF-TOKEN'] = csrfToken;
    }
  }
  return config;
});

// Response interceptor to handle 401s and token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If 401 and not already retrying, and not on the login/refresh routes
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url.includes('/login') &&
      !originalRequest.url.includes('/token/refresh')
    ) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh token
        await api.post('/token/refresh');
        
        // Update CSRF token for the retried request if it's mutating
        const method = originalRequest.method?.toUpperCase();
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
          const newCsrfToken = getCsrfToken();
          if (newCsrfToken) {
            originalRequest.headers['X-CSRF-TOKEN'] = newCsrfToken;
          }
        }
        
        return api(originalRequest);
      } catch (refreshError) {
        // If refresh fails, we are truly logged out. 
        // We reject the promise and let AuthContext handle the unauthenticated state.
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

// --- API Functions ---

export const authService = {
  login: (identifier, password) => api.post('/login', { identifier, password }),
  register: (userData) => api.post('/register', userData),
  logout: () => api.post('/logout'),
  forgotPassword: (identifier, otp) => api.post('/forgot_password', { identifier, otp }),
  resetPassword: (token, new_password) => api.post('/reset_password', { token, new_password }),
  verifyResetToken: (token) => api.get(`/verify_reset_token/${token}`),
};

export const userService = {
  getDashboard: async () => {
    const res = await api.get('/dashboard');
    return res.data.data.user;
  },
  updateProfile: (data) => api.post('/dashboard/update_profile', data),
  verifyUpdateOtp: (otp) => api.post('/dashboard/verify_update_otp', { otp }),
  resendUpdateOtp: () => api.post('/dashboard/resend_update_otp'),
};

export const adminService = {
  getDashboard: async () => {
    const res = await api.get('/admin/dashboard');
    return {
      stats: {
        total_users: res.data.data.total_users,
        active_users: res.data.data.active_users
      },
      users: res.data.data.users
    };
  },
  addUser: (data) => api.post('/admin/add_user', data),
  deleteUser: (id) => api.delete(`/admin/delete_user/${id}`),
  setRole: (user_id, role) => api.patch('/admin/set_role', { user_id, role }),
};

export default api;

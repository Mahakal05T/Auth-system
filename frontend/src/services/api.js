import axios from 'axios';

// The Vite proxy handles routing these to http://127.0.0.1:5000
const api = axios.create({
  baseURL: '', // Empty because proxy will intercept /login, /register, etc.
  withCredentials: true, // Crucial for cookie-based JWTs
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper to get CSRF token from cookies
const getCsrfToken = () => {
  const match = document.cookie.match(new RegExp('(^| )csrf_access_token=([^;]+)'));
  return match ? match[2] : null;
};

// Request interceptor to attach CSRF token for mutating requests
api.interceptors.request.use((config) => {
  const method = config.method?.toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfToken = getCsrfToken();
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
        // Redirect to login handled by AuthContext or Router usually, 
        // but we can trigger a hard reload/redirect here as a fallback
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

// Helper to parse HTML responses into JSON
const parseHtmlResponse = (html, type) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  
  if (type === 'dashboard') {
    // Parse user profile from dashboard.html
    try {
      const name = doc.getElementById('profile_name')?.value || '';
      const email = doc.getElementById('profile_email')?.value || '';
      const phone = doc.getElementById('profile_phone')?.value || '';
      
      // Extract emp_id from the read-only div next to the profile_name input
      const form = doc.getElementById('profileForm');
      const empIdEl = form?.querySelector('.bg-gray-100 .text-gray-800');
      const emp_id = empIdEl?.textContent?.trim() || '';
      
      // Extract role/department/status from the left profile summary section
      // Since classes are somewhat generic, we look for labels like "Role", "Department"
      const profileSummary = doc.querySelector('section.lg\\:col-span-1');
      let department = '';
      let role = '';
      let status = '';
      let created_at = '';
      
      if (profileSummary) {
        const divs = profileSummary.querySelectorAll('.text-gray-500');
        divs.forEach(div => {
          const label = div.textContent?.trim();
          const nextDiv = div.nextElementSibling;
          if (label === 'Department') department = nextDiv?.textContent?.trim();
          if (label === 'Role') role = nextDiv?.textContent?.trim().toLowerCase();
          if (label === 'Status') status = nextDiv?.textContent?.includes('Active') ? 'active' : 'inactive';
          if (label === 'Account created') created_at = nextDiv?.textContent?.trim();
        });
      }
      
      return { name, email, phone, emp_id, department, role, status, created_at };
    } catch (e) {
      console.error("Failed to parse dashboard HTML", e);
      return null;
    }
  }
  
  if (type === 'admin') {
    // Parse admin dashboard stats and users list
    try {
      // Stats are in text-3xl tags
      const statEls = doc.querySelectorAll('.text-3xl.font-bold');
      const total_users = statEls[0]?.textContent?.trim() || '0';
      const active_users = statEls[1]?.textContent?.trim() || '0';
      
      // Users table
      const users = [];
      const rows = doc.querySelectorAll('#userTableBody tr');
      rows.forEach(row => {
        const role = row.getAttribute('data-role');
        const department = row.getAttribute('data-department');
        const cells = row.querySelectorAll('td');
        
        if (cells.length >= 6) {
          const emp_id = cells[0].textContent.trim();
          const name = cells[1].textContent.trim();
          const email = cells[2].textContent.trim();
          const phone = cells[3].textContent.trim();
          
          // Get ID from delete button for admin actions
          const deleteBtn = row.querySelector('.deleteUserBtn');
          const id = deleteBtn ? deleteBtn.getAttribute('data-user-id') : null;
          
          users.push({ id, emp_id, name, email, phone, role, department });
        }
      });
      
      return { stats: { total_users, active_users }, users };
    } catch (e) {
      console.error("Failed to parse admin dashboard HTML", e);
      return { stats: {}, users: [] };
    }
  }
  
  return null;
};

// --- API Functions ---

export const authService = {
  login: (identifier, password) => api.post('/login', { identifier, password }),
  register: (userData) => api.post('/register', userData),
  logout: () => api.post('/logout'),
  forgotPassword: (identifier, otp) => api.post('/forgot_password', { identifier, otp }),
  resetPassword: (token, new_password) => api.post('/reset_password', { token, new_password }),
};

export const userService = {
  // Fetch HTML and parse to JSON
  getDashboard: async () => {
    const res = await api.get('/dashboard');
    return parseHtmlResponse(res.data, 'dashboard');
  },
  updateProfile: (data) => api.post('/dashboard/update_profile', data),
  verifyUpdateOtp: (otp) => api.post('/dashboard/verify_update_otp', { otp }),
  resendUpdateOtp: () => api.post('/dashboard/resend_update_otp'),
};

export const adminService = {
  getDashboard: async () => {
    const res = await api.get('/admin/dashboard');
    return parseHtmlResponse(res.data, 'admin');
  },
  addUser: (data) => api.post('/admin/add_user', data),
  deleteUser: (id) => api.delete(`/admin/delete_user/${id}`),
  setRole: (user_id, role) => api.patch('/admin/set_role', { user_id, role }),
};

export default api;

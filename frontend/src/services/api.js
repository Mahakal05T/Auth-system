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
  login: (email, password) => api.post('/login', { email, password }),
  register: (userData) => api.post('/register', userData),
  logout: () => api.post('/logout'),
  getMe: () => api.get('/me'),
  forgotPassword: (email, otp) => api.post('/forgot_password', { email, otp }),
  resetPassword: (token, new_password) => api.post('/reset_password', { token, new_password }),
  verifyResetToken: (token) => api.get(`/verify_reset_token/${token}`),
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

export const productService = {
  getCategories: async () => {
    const res = await api.get('/categories');
    return res.data.categories || [];
  },
  getCategory: async (identifier) => {
    const res = await api.get(`/categories/${identifier}`);
    return res.data.category;
  },
  getProducts: async (params = {}) => {
    const res = await api.get('/products', { params });
    return res.data.data;
  },
  getProduct: async (id) => {
    const res = await api.get(`/products/${id}`);
    return res.data.product;
  },
  getDeals: async () => {
    const res = await api.get('/products/deals');
    return res.data.deals || [];
  },
  adminCreateProduct: (data) => api.post('/admin/products', data),
  adminUpdateProduct: (id, data) => api.put(`/admin/products/${id}`, data),
  adminDeleteProduct: (id) => api.delete(`/admin/products/${id}`),
  adminCreateCategory: (data) => api.post('/admin/categories', data),
};

export const cartService = {
  getCart: async () => {
    const res = await api.get('/cart');
    return res.data.cart;
  },
  addToCart: async (productId, quantity = 1) => {
    const res = await api.post('/cart/items', { product_id: productId, quantity });
    return res.data;
  },
  updateItem: async (itemId, quantity) => {
    const res = await api.put(`/cart/items/${itemId}`, { quantity });
    return res.data.cart;
  },
  removeItem: async (itemId) => {
    const res = await api.delete(`/cart/items/${itemId}`);
    return res.data.cart;
  },
  clearCart: async () => {
    const res = await api.delete('/cart/clear');
    return res.data.cart;
  },
  syncGuestCart: async (items) => {
    const res = await api.post('/cart/sync', { items });
    return res.data.cart;
  },
};

export const wishlistService = {
  getWishlist: async () => {
    const res = await api.get('/wishlist');
    return res.data.wishlist;
  },
  addToWishlist: async (productId) => {
    const res = await api.post('/wishlist/items', { product_id: productId });
    return res.data;
  },
  removeFromWishlist: async (productId) => {
    const res = await api.delete(`/wishlist/items/${productId}`);
    return res.data;
  },
  moveToCart: async (productId) => {
    const res = await api.post('/wishlist/move-to-cart', { product_id: productId });
    return res.data;
  },
  syncGuestWishlist: async (items) => {
    const res = await api.post('/wishlist/sync', { items });
    return res.data.wishlist;
  },
};

export const addressService = {
  getAddresses: async () => {
    const res = await api.get('/addresses');
    return res.data.addresses || [];
  },
  addAddress: async (data) => {
    const res = await api.post('/addresses', data);
    return res.data;
  },
  updateAddress: async (id, data) => {
    const res = await api.put(`/addresses/${id}`, data);
    return res.data;
  },
  deleteAddress: async (id) => {
    const res = await api.delete(`/addresses/${id}`);
    return res.data;
  },
  setDefaultAddress: async (id) => {
    const res = await api.patch(`/addresses/${id}/default`);
    return res.data;
  },
};

export const checkoutService = {
  validateCoupon: async (code, subtotal) => {
    const res = await api.post('/checkout/validate-coupon', { code, subtotal });
    return res.data;
  },
  previewCheckout: async (data = {}) => {
    const res = await api.post('/checkout/preview', data);
    return res.data.preview;
  },
  placeOrder: async (data) => {
    const res = await api.post('/checkout/place-order', data);
    return res.data;
  },
};

export const orderService = {
  getMyOrders: async () => {
    const res = await api.get('/orders');
    return res.data.orders || [];
  },
  getOrderDetails: async (identifier) => {
    const res = await api.get(`/orders/${identifier}`);
    return res.data.order;
  },
  cancelOrder: async (identifier) => {
    const res = await api.post(`/orders/${identifier}/cancel`);
    return res.data;
  },
  trackOrder: async (identifier) => {
    const res = await api.get(`/orders/${identifier}/track`);
    return res.data.tracking;
  },
};

export const adminProductService = {
  getProducts: async (params = {}) => {
    const res = await api.get('/admin/products', { params });
    return res.data;
  },
  createProduct: async (data) => {
    const res = await api.post('/admin/products', data);
    return res.data;
  },
  updateProduct: async (id, data) => {
    const res = await api.put(`/admin/products/${id}`, data);
    return res.data;
  },
  deleteProduct: async (id) => {
    const res = await api.delete(`/admin/products/${id}`);
    return res.data;
  },
  toggleStatus: async (id) => {
    const res = await api.patch(`/admin/products/${id}/toggle-status`);
    return res.data;
  },
};

export const adminOrderService = {
  getOrders: async (params = {}) => {
    const res = await api.get('/admin/orders', { params });
    return res.data;
  },
  getOrderDetail: async (id) => {
    const res = await api.get(`/admin/orders/${id}`);
    return res.data.order;
  },
  updateOrderStatus: async (id, status) => {
    const res = await api.patch(`/admin/orders/${id}/status`, { status });
    return res.data;
  },
};

export const adminInventoryService = {
  getInventory: async (params = {}) => {
    const res = await api.get('/admin/inventory', { params });
    return res.data;
  },
  adjustStock: async (data) => {
    const res = await api.post('/admin/inventory/adjust', data);
    return res.data;
  },
  getLogs: async (params = {}) => {
    const res = await api.get('/admin/inventory/logs', { params });
    return res.data;
  },
};

export const reviewService = {
  getProductReviews: async (productId) => {
    const res = await api.get(`/products/${productId}/reviews`);
    return res.data;
  },
  submitReview: async (productId, data) => {
    const res = await api.post(`/products/${productId}/reviews`, data);
    return res.data;
  },
  deleteReview: async (productId, reviewId) => {
    const res = await api.delete(`/products/${productId}/reviews/${reviewId}`);
    return res.data;
  },
};

export const adminReviewService = {
  getReviews: async (params = {}) => {
    const res = await api.get('/admin/reviews', { params });
    return res.data;
  },
  updateStatus: async (reviewId, status) => {
    const res = await api.patch(`/admin/reviews/${reviewId}/status`, { status });
    return res.data;
  },
  postReply: async (reviewId, replyText) => {
    const res = await api.post(`/admin/reviews/${reviewId}/reply`, { reply_text: replyText });
    return res.data;
  },
  deleteReply: async (reviewId) => {
    const res = await api.delete(`/admin/reviews/${reviewId}/reply`);
    return res.data;
  },
  deleteReview: async (reviewId) => {
    const res = await api.delete(`/admin/reviews/${reviewId}`);
    return res.data;
  },
};

export const couponService = {
  getAvailableCoupons: async () => {
    const res = await api.get('/coupons/available');
    return res.data.coupons || [];
  },
  validateCoupon: async (code, subtotal) => {
    const res = await api.post('/checkout/validate-coupon', { code, subtotal });
    return res.data;
  },
};

export const adminCouponService = {
  getCoupons: async (params = {}) => {
    const res = await api.get('/admin/coupons', { params });
    return res.data;
  },
  createCoupon: async (data) => {
    const res = await api.post('/admin/coupons', data);
    return res.data;
  },
  updateCoupon: async (id, data) => {
    const res = await api.put(`/admin/coupons/${id}`, data);
    return res.data;
  },
  toggleCouponStatus: async (id) => {
    const res = await api.patch(`/admin/coupons/${id}/toggle-status`);
    return res.data;
  },
  deleteCoupon: async (id) => {
    const res = await api.delete(`/admin/coupons/${id}`);
    return res.data;
  },
  getCouponUsages: async (id) => {
    const res = await api.get(`/admin/coupons/${id}/usages`);
    return res.data.usages || [];
  },
};

export const categoryService = {
  getCategories: async () => {
    const res = await api.get('/categories');
    return res.data;
  },
  getCategory: async (identifier) => {
    const res = await api.get(`/categories/${identifier}`);
    return res.data.category;
  },
};

export const adminCategoryService = {
  getCategories: async (params = {}) => {
    const res = await api.get('/admin/categories', { params });
    return res.data;
  },
  createCategory: async (data) => {
    const res = await api.post('/admin/categories', data);
    return res.data;
  },
  updateCategory: async (id, data) => {
    const res = await api.put(`/admin/categories/${id}`, data);
    return res.data;
  },
  toggleCategoryStatus: async (id) => {
    const res = await api.patch(`/admin/categories/${id}/toggle-status`);
    return res.data;
  },
  reorderCategories: async (orders) => {
    const res = await api.patch('/admin/categories/reorder', { orders });
    return res.data;
  },
  deleteCategory: async (id, params = {}) => {
    const res = await api.delete(`/admin/categories/${id}`, { params });
    return res.data;
  },
};

export const returnService = {
  requestReturn: async (data) => {
    const res = await api.post('/returns/request', data);
    return res.data;
  },
  getMyReturns: async () => {
    const res = await api.get('/returns/my-returns');
    return res.data.returns || [];
  },
};

export const adminReturnService = {
  getReturns: async (params = {}) => {
    const res = await api.get('/admin/returns', { params });
    return res.data;
  },
  updateReturnStatus: async (returnId, data) => {
    const res = await api.patch(`/admin/returns/${returnId}/status`, data);
    return res.data;
  },
  addNotes: async (returnId, notes) => {
    const res = await api.post(`/admin/returns/${returnId}/notes`, { notes });
    return res.data;
  },
};

export const adminAnalyticsService = {
  getOverview: async (timeframe = '30d') => {
    const res = await api.get('/admin/analytics/overview', { params: { timeframe } });
    return res.data;
  },
};

export const settingsService = {
  getPublicSettings: async () => {
    const res = await api.get('/settings/public');
    return res.data.settings || {};
  },
};

export const adminSettingsService = {
  getSettings: async () => {
    const res = await api.get('/admin/settings');
    return res.data;
  },
  updateSettings: async (settings) => {
    const res = await api.put('/admin/settings', { settings });
    return res.data;
  },
  resetSettings: async () => {
    const res = await api.post('/admin/settings/reset');
    return res.data;
  },
};

export default api;

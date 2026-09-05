import { useState, useRef, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { 
  Search, ShoppingCart, Heart, User, LogOut, Sun, Moon, 
  Menu, X, ChevronDown, Package, Shield, Sparkles, Tag, SlidersHorizontal 
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useCart } from '../../context/CartContext';
import { useWishlist } from '../../context/WishlistContext';
import { settingsService } from '../../services/api';

export function StorefrontNavbar() {
  const { user, role, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { totalItems: cartCount } = useCart();
  const { wishlistCount } = useWishlist();
  const navigate = useNavigate();
  const location = useLocation();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All Categories');
  const [isAccountOpen, setIsAccountOpen] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [publicSettings, setPublicSettings] = useState(null);
  const accountRef = useRef(null);

  useEffect(() => {
    settingsService.getPublicSettings().then(setPublicSettings).catch(() => {});
  }, []);

  const categories = [
    'All Categories',
    'Electronics',
    'Fashion & Apparel',
    'Home & Kitchen',
    'Beauty & Personal Care',
    'Sports & Outdoors',
    'Books & Stationery'
  ];

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (accountRef.current && !accountRef.current.contains(e.target)) {
        setIsAccountOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/products?q=${encodeURIComponent(searchQuery.trim())}${selectedCategory !== 'All Categories' ? `&category=${encodeURIComponent(selectedCategory)}` : ''}`);
      setIsMobileMenuOpen(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    setIsAccountOpen(false);
    navigate('/');
  };

  return (
    <header className="sticky top-0 z-40 w-full bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 shadow-xs transition-colors">
      {/* Top Notification / Promo Bar */}
      <div className="bg-gradient-to-r from-brand-600 via-indigo-600 to-purple-600 text-white text-xs font-medium py-1.5 px-4 text-center flex items-center justify-center gap-2">
        <Sparkles className="w-3.5 h-3.5 animate-pulse shrink-0" />
        <span className="truncate">
          {publicSettings?.announcement_banner || '✨ Enjoy 10% OFF your first order with code APEX10 • Free shipping over $100!'}
        </span>
      </div>

      {/* Main Navigation Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-18 gap-3 sm:gap-6">
          
          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="lg:hidden p-2 rounded-lg text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none"
            aria-label="Toggle menu"
          >
            {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>

          {/* Brand Logo */}
          <Link to="/" className="flex items-center gap-2 shrink-0">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-brand-600 to-indigo-500 flex items-center justify-center shadow-md shadow-brand-500/20 text-white font-black text-xl">
              {(publicSettings?.store_name || 'ApexStore').charAt(0).toUpperCase()}
            </div>
            <div className="flex flex-col">
              <span className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-gray-900 via-brand-700 to-indigo-600 dark:from-white dark:via-brand-300 dark:to-indigo-400 bg-clip-text text-transparent">
                {publicSettings?.store_name || 'ApexStore'}
              </span>
              <span className="text-[10px] uppercase tracking-widest text-gray-400 font-semibold -mt-1 hidden sm:block">
                {publicSettings?.store_tagline || 'Modern E-Commerce'}
              </span>
            </div>
          </Link>

          {/* Search Bar (Desktop) */}
          <form onSubmit={handleSearch} className="hidden md:flex flex-1 max-w-2xl items-center relative">
            <div className="flex w-full items-center rounded-full border border-gray-300 dark:border-gray-700 bg-gray-50/80 dark:bg-gray-800/80 focus-within:border-brand-500 focus-within:ring-2 focus-within:ring-brand-500/20 focus-within:bg-white dark:focus-within:bg-gray-900 transition-all overflow-hidden">
              
              {/* Category selector */}
              <div className="hidden lg:flex items-center border-r border-gray-300 dark:border-gray-700 px-3 text-xs text-gray-600 dark:text-gray-300 bg-transparent shrink-0">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="bg-transparent border-none outline-none py-2 pr-1 font-medium cursor-pointer"
                >
                  {categories.map((c) => (
                    <option key={c} value={c} className="bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100">
                      {c}
                    </option>
                  ))}
                </select>
              </div>

              {/* Input */}
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search products, brands, essentials..."
                className="w-full px-4 py-2.5 text-sm bg-transparent border-none text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none"
              />

              {/* Search Button */}
              <button
                type="submit"
                className="bg-brand-600 hover:bg-brand-700 text-white px-5 py-2.5 rounded-full mr-1 flex items-center justify-center transition-colors"
                aria-label="Submit search"
              >
                <Search className="w-4 h-4" />
              </button>
            </div>
          </form>

          {/* Right Action Icons */}
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="p-2.5 rounded-full text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              title="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5 text-amber-400" /> : <Moon className="w-5 h-5" />}
            </button>

            {/* Wishlist Link */}
            <Link
              to="/wishlist"
              className="p-2.5 rounded-full text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors relative"
              title="Wishlist"
            >
              <Heart className="w-5 h-5" />
              {wishlistCount > 0 && (
                <span className="absolute top-1 right-1 w-4 h-4 bg-rose-500 text-white rounded-full text-[10px] font-bold flex items-center justify-center animate-scale-in">
                  {wishlistCount}
                </span>
              )}
            </Link>

            {/* Cart Link */}
            <Link
              to="/cart"
              className="flex items-center gap-2 py-2 px-3 sm:px-3.5 rounded-full bg-brand-50 hover:bg-brand-100 dark:bg-brand-950/60 dark:hover:bg-brand-900/60 text-brand-700 dark:text-brand-300 transition-colors relative border border-brand-200/50 dark:border-brand-800/50"
              title="Shopping Cart"
            >
              <ShoppingCart className="w-5 h-5 text-brand-600 dark:text-brand-400" />
              <span className="text-xs font-semibold hidden sm:inline-block">Cart</span>
              <span className="w-5 h-5 bg-brand-600 text-white rounded-full text-[11px] font-bold flex items-center justify-center">
                {cartCount}
              </span>
            </Link>

            {/* User Account / Login Dropdown */}
            <div className="relative" ref={accountRef}>
              {user ? (
                <div>
                  <button
                    onClick={() => setIsAccountOpen(!isAccountOpen)}
                    className="flex items-center gap-2 py-1.5 px-3 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors border border-gray-200 dark:border-gray-700"
                  >
                    <div className="w-7 h-7 rounded-full bg-brand-600 text-white flex items-center justify-center font-bold text-xs uppercase">
                      {user.name ? user.name.charAt(0) : 'U'}
                    </div>
                    <span className="text-xs font-medium text-gray-800 dark:text-gray-200 max-w-[100px] truncate hidden md:inline-block">
                      {user.name || 'Account'}
                    </span>
                    <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                  </button>

                  {/* Dropdown Menu */}
                  {isAccountOpen && (
                    <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-gray-900 rounded-2xl shadow-xl border border-gray-200 dark:border-gray-800 py-2 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                      <div className="px-4 py-2.5 border-b border-gray-100 dark:border-gray-800">
                        <p className="text-xs font-medium text-gray-500 dark:text-gray-400">Signed in as</p>
                        <p className="text-sm font-semibold text-gray-900 dark:text-white truncate">{user.email}</p>
                        <span className="inline-block mt-1 text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-300">
                          {role}
                        </span>
                      </div>

                      {role === 'admin' && (
                        <Link
                          to="/admin"
                          onClick={() => setIsAccountOpen(false)}
                          className="flex items-center gap-2.5 px-4 py-2 text-sm text-brand-600 dark:text-brand-400 font-semibold hover:bg-brand-50 dark:hover:bg-brand-950/40"
                        >
                          <Shield className="w-4 h-4" /> Admin Portal
                        </Link>
                      )}

                      <Link
                        to="/account"
                        onClick={() => setIsAccountOpen(false)}
                        className="flex items-center gap-2.5 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                      >
                        <User className="w-4 h-4 text-gray-400" /> My Profile
                      </Link>

                      <Link
                        to="/orders"
                        onClick={() => setIsAccountOpen(false)}
                        className="flex items-center gap-2.5 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                      >
                        <Package className="w-4 h-4 text-gray-400" /> My Orders
                      </Link>

                      <Link
                        to="/wishlist"
                        onClick={() => setIsAccountOpen(false)}
                        className="flex items-center gap-2.5 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                      >
                        <Heart className="w-4 h-4 text-gray-400" /> My Wishlist
                      </Link>

                      <div className="border-t border-gray-100 dark:border-gray-800 my-1" />

                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/30 text-left"
                      >
                        <LogOut className="w-4 h-4" /> Sign Out
                      </button>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Link
                    to="/login"
                    className="flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-semibold bg-gray-900 text-white hover:bg-gray-800 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100 transition-colors shadow-xs"
                  >
                    <User className="w-3.5 h-3.5" /> Sign In
                  </Link>
                </div>
              )}
            </div>

          </div>
        </div>

        {/* Mobile Search Bar */}
        <div className="md:hidden pb-3">
          <form onSubmit={handleSearch} className="flex items-center rounded-full border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 overflow-hidden">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search products..."
              className="w-full px-4 py-2 text-xs bg-transparent border-none text-gray-900 dark:text-white focus:outline-none"
            />
            <button type="submit" className="bg-brand-600 text-white p-2 mr-1 rounded-full">
              <Search className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </div>

      {/* Secondary Category Navigation Bar */}
      <nav className="border-t border-gray-100 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-900/50 overflow-x-auto scrollbar-none">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-6 text-xs font-medium py-2.5">
          <div className="flex items-center gap-5 sm:gap-7 shrink-0">
            <Link 
              to="/products" 
              className={`flex items-center gap-1 hover:text-brand-600 dark:hover:text-brand-400 transition-colors ${location.pathname === '/products' ? 'text-brand-600 dark:text-brand-400 font-bold' : 'text-gray-700 dark:text-gray-300'}`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" /> All Products
            </Link>
            <Link to="/products?category=Electronics" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors text-gray-600 dark:text-gray-400">
              Electronics
            </Link>
            <Link to="/products?category=Fashion" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors text-gray-600 dark:text-gray-400">
              Fashion & Apparel
            </Link>
            <Link to="/products?category=Home" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors text-gray-600 dark:text-gray-400">
              Home & Living
            </Link>
            <Link to="/products?category=Beauty" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors text-gray-600 dark:text-gray-400">
              Beauty & Wellness
            </Link>
            <Link to="/products?badge=deal" className="flex items-center gap-1 text-rose-600 dark:text-rose-400 font-bold hover:underline">
              <Tag className="w-3.5 h-3.5" /> Today's Deals
            </Link>
          </div>

          <div className="hidden lg:flex items-center gap-4 text-gray-500 dark:text-gray-400 shrink-0">
            <span className="flex items-center gap-1 text-[11px]">
              <Shield className="w-3.5 h-3.5 text-emerald-500" /> Buyer Protection Verified
            </span>
          </div>
        </div>
      </nav>

      {/* Mobile Menu Drawer */}
      {isMobileMenuOpen && (
        <div className="lg:hidden border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 px-4 py-4 space-y-3">
          <div className="font-semibold text-xs text-gray-400 uppercase tracking-wider">Browse Store</div>
          <div className="grid grid-cols-2 gap-2">
            <Link
              to="/products"
              onClick={() => setIsMobileMenuOpen(false)}
              className="px-3 py-2 rounded-lg bg-gray-50 dark:bg-gray-800 text-xs font-medium text-gray-800 dark:text-gray-200"
            >
              All Products
            </Link>
            <Link
              to="/products?badge=deal"
              onClick={() => setIsMobileMenuOpen(false)}
              className="px-3 py-2 rounded-lg bg-rose-50 dark:bg-rose-950/40 text-xs font-medium text-rose-600 dark:text-rose-400"
            >
              Today's Deals
            </Link>
            <Link
              to="/products?category=Electronics"
              onClick={() => setIsMobileMenuOpen(false)}
              className="px-3 py-2 rounded-lg bg-gray-50 dark:bg-gray-800 text-xs font-medium text-gray-800 dark:text-gray-200"
            >
              Electronics
            </Link>
            <Link
              to="/products?category=Fashion"
              onClick={() => setIsMobileMenuOpen(false)}
              className="px-3 py-2 rounded-lg bg-gray-50 dark:bg-gray-800 text-xs font-medium text-gray-800 dark:text-gray-200"
            >
              Fashion
            </Link>
          </div>
          {user && (
            <div className="pt-2 border-t border-gray-100 dark:border-gray-800 flex flex-col gap-1">
              <Link
                to="/account"
                onClick={() => setIsMobileMenuOpen(false)}
                className="py-2 text-xs font-medium text-gray-700 dark:text-gray-300"
              >
                My Profile & Addresses
              </Link>
              <Link
                to="/orders"
                onClick={() => setIsMobileMenuOpen(false)}
                className="py-2 text-xs font-medium text-gray-700 dark:text-gray-300"
              >
                My Orders
              </Link>
            </div>
          )}
        </div>
      )}
    </header>
  );
}

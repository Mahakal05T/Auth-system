import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  ArrowRight, Sparkles, Star, ShoppingCart, Heart, Shield, 
  Flame, Clock, Percent, Award, ChevronRight, CheckCircle2, Loader2 
} from 'lucide-react';
import toast from 'react-hot-toast';
import { productService } from '../../services/api';
import { useCart } from '../../context/CartContext';
import { useWishlist } from '../../context/WishlistContext';

// Seed demo products for instant hydration
export const demoProducts = [
  {
    id: 1,
    name: 'AeroPulse Wireless Noise-Cancelling Headphones',
    category: 'Electronics',
    price: 189.99,
    discount_price: 149.99,
    rating: 4.8,
    reviewsCount: 328,
    badge: 'Deal of the Day',
    inStock: true,
    image: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80',
    description: 'Ultra-low latency audio with adaptive hybrid noise cancellation and 40-hour playtime.'
  },
  {
    id: 2,
    name: 'Titan Chrono Smartwatch Ultra with Titanium Frame',
    category: 'Electronics',
    price: 299.00,
    discount_price: 249.00,
    rating: 4.9,
    reviewsCount: 512,
    badge: 'Best Seller',
    inStock: true,
    image: 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=600&q=80',
    description: 'Precision sapphire glass, ECG monitoring, cellular standby, and waterproof up to 50 meters.'
  },
  {
    id: 3,
    name: 'Merino Wool Minimalist Knit Sweater',
    category: 'Fashion',
    price: 79.50,
    discount_price: null,
    rating: 4.7,
    reviewsCount: 184,
    badge: 'Trending',
    inStock: true,
    image: 'https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=600&q=80',
    description: 'Superfine 100% natural merino wool offering supreme breathability and modern tailored fit.'
  },
  {
    id: 4,
    name: 'Precision Barista Espresso Machine with Steam Wand',
    category: 'Home',
    price: 449.99,
    discount_price: 399.99,
    rating: 4.9,
    reviewsCount: 420,
    badge: '25% OFF',
    inStock: true,
    image: 'https://images.unsplash.com/photo-1570968915860-54d5c301fa9f?auto=format&fit=crop&w=600&q=80',
    description: '15-bar Italian pump with integrated thermo-coil system and micro-foam milk texturing.'
  },
  {
    id: 5,
    name: 'HydraGlow Botanical Facial Serum Complex',
    category: 'Beauty',
    price: 42.00,
    discount_price: 34.00,
    rating: 4.6,
    reviewsCount: 96,
    badge: 'Organic',
    inStock: true,
    image: 'https://images.unsplash.com/photo-1620916566398-39f1143ab7be?auto=format&fit=crop&w=600&q=80',
    description: 'Formulated with cold-pressed rosehip seed oil, hyaluronic acid, and niacinamide for radiant skin.'
  },
  {
    id: 6,
    name: 'CarbonFiber Ultralight Ergonomic Mechanical Keyboard',
    category: 'Electronics',
    price: 139.00,
    discount_price: null,
    rating: 4.8,
    reviewsCount: 215,
    badge: 'Popular',
    inStock: true,
    image: 'https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=600&q=80',
    description: 'Hot-swappable custom lubricated switches, wireless multi-device pairing, and RGB underglow.'
  }
];

export default function HomePage() {
  const [categories, setCategories] = useState([]);
  const [deals, setDeals] = useState([]);
  const [trending, setTrending] = useState(demoProducts);
  const [isLoading, setIsLoading] = useState(true);
  const { addToCart } = useCart();
  const { isWishlisted, toggleWishlist } = useWishlist();

  useEffect(() => {
    let isMounted = true;
    async function loadData() {
      try {
        const [cats, dealsData, prodsData] = await Promise.allSettled([
          productService.getCategories(),
          productService.getDeals(),
          productService.getProducts({ limit: 8 })
        ]);

        if (isMounted) {
          if (cats.status === 'fulfilled' && cats.value.length > 0) {
            setCategories(cats.value);
          }
          if (dealsData.status === 'fulfilled' && dealsData.value.length > 0) {
            setDeals(dealsData.value);
          }
          if (prodsData.status === 'fulfilled' && prodsData.value?.products?.length > 0) {
            setTrending(prodsData.value.products);
          }
        }
      } catch (err) {
        console.warn('Backend storefront fallback mode active:', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    loadData();
    return () => { isMounted = false; };
  }, []);

  const handleAddToCart = (product) => {
    addToCart(product, 1);
  };

  const displayCategories = categories.length > 0 ? categories : [
    { name: 'Electronics', slug: 'electronics', product_count: '120+' },
    { name: 'Fashion', slug: 'fashion', product_count: '340+' },
    { name: 'Home & Living', slug: 'home', product_count: '85+' },
    { name: 'Beauty & Wellness', slug: 'beauty', product_count: '92+' },
    { name: 'Sports & Outdoors', slug: 'sports', product_count: '64+' },
  ];

  const displayDeals = deals.length > 0 ? deals : demoProducts.filter(p => p.discount_price);

  return (
    <div className="space-y-12 sm:space-y-16 animate-in fade-in duration-500">
      {/* 1. Hero Showcase Banner */}
      <section className="relative rounded-3xl overflow-hidden bg-gradient-to-br from-gray-900 via-brand-950 to-indigo-950 text-white shadow-2xl p-6 sm:p-12 lg:p-16 border border-brand-800/30">
        <div className="relative z-10 max-w-2xl space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-brand-500/20 border border-brand-400/30 text-brand-300 text-xs font-semibold backdrop-blur-md">
            <Sparkles className="w-3.5 h-3.5 text-brand-400" />
            New Season Collection 2026
          </div>

          <h1 className="text-3xl sm:text-5xl lg:text-6xl font-black tracking-tight leading-[1.1]">
            Next-Gen Tech & Modern Living.
          </h1>

          <p className="text-gray-300 text-sm sm:text-base leading-relaxed max-w-xl">
            Experience authentic high-grade electronics, sustainable designer fashion, and top-rated home essentials with instant shipping and verified customer ratings.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <Link
              to="/products"
              className="px-6 py-3.5 rounded-full bg-brand-600 hover:bg-brand-500 text-white font-bold text-sm flex items-center gap-2 shadow-lg shadow-brand-600/30 transition-all hover:scale-105"
            >
              Shop Catalog Now <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              to="/products?badge=deal"
              className="px-6 py-3.5 rounded-full bg-white/10 hover:bg-white/20 text-white font-semibold text-sm border border-white/20 backdrop-blur-md transition-colors"
            >
              Explore Today's Deals
            </Link>
          </div>

          {/* Key micro-perks */}
          <div className="pt-4 flex flex-wrap items-center gap-6 text-xs text-gray-400 border-t border-white/10">
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-emerald-400" /> 100% Genuine Brands</span>
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-emerald-400" /> 30-Day Free Return</span>
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-emerald-400" /> Free Shipping $49+</span>
          </div>
        </div>

        {/* Decorative ambient gradient backdrop */}
        <div className="absolute right-[-10%] top-[-20%] w-[500px] h-[500px] rounded-full bg-brand-500/20 blur-[120px] pointer-events-none" />
        <div className="absolute right-[10%] bottom-[-20%] w-[400px] h-[400px] rounded-full bg-purple-600/20 blur-[100px] pointer-events-none" />
      </section>

      {/* 2. Featured Category Pills */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
              Featured Categories
            </h2>
            <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400 mt-0.5">
              Curated collections suited for your lifestyle
            </p>
          </div>
          <Link
            to="/products"
            className="text-xs font-semibold text-brand-600 dark:text-brand-400 hover:underline flex items-center gap-1"
          >
            All Categories <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          {displayCategories.map((cat) => (
            <Link
              key={cat.slug || cat.name}
              to={`/products?category=${encodeURIComponent(cat.slug || cat.name)}`}
              className="group p-5 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 hover:border-brand-500 dark:hover:border-brand-500 transition-all hover:shadow-md flex flex-col justify-between"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-2xl">🛍️</span>
                <ChevronRight className="w-4 h-4 text-gray-400 group-hover:text-brand-500 group-hover:translate-x-1 transition-all" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-gray-900 dark:text-white group-hover:text-brand-600 transition-colors">
                  {cat.name}
                </h3>
                <span className="text-xs text-gray-500 dark:text-gray-400">
                  {cat.product_count || 'Catalog'}
                </span>
              </div>
            </Link>
          ))}
        </div>
      </section>

      {/* 3. Deals of the Day Carousel / Grid */}
      <section className="p-6 sm:p-8 rounded-3xl bg-gradient-to-r from-rose-50 via-amber-50 to-orange-50 dark:from-rose-950/20 dark:via-gray-900 dark:to-orange-950/20 border border-rose-200 dark:border-rose-900/30 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-rose-600 text-white flex items-center justify-center shadow-lg shadow-rose-600/30">
              <Flame className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl sm:text-2xl font-black text-gray-900 dark:text-white">
                  Deals of the Day
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-extrabold bg-rose-600 text-white uppercase tracking-wider animate-bounce">
                  Limited Time
                </span>
              </div>
              <p className="text-xs text-gray-600 dark:text-gray-400">
                Massive discounts on premium tech and essentials — ends in 07:42:19
              </p>
            </div>
          </div>

          <Link
            to="/products?badge=deal"
            className="px-4 py-2 rounded-full bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs font-bold shadow-xs hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center gap-1.5 w-fit"
          >
            View All Deals <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
          {displayDeals.slice(0, 4).map((product) => {
            const currentPrice = product.discount_price || product.price;
            const originalPrice = product.discount_price ? product.price : (product.originalPrice || null);
            const savings = originalPrice ? (originalPrice - currentPrice) : 0;

            return (
              <div
                key={product.id}
                className="group relative rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 p-4 shadow-sm hover:shadow-xl transition-all duration-300 flex flex-col justify-between"
              >
                {/* Wishlist Button */}
                <button
                  onClick={() => toggleWishlist(product)}
                  className={`absolute top-6 right-6 z-10 p-2 rounded-full backdrop-blur-md transition-colors ${
                    isWishlisted(product.id) 
                      ? 'bg-rose-500 text-white' 
                      : 'bg-white/80 dark:bg-gray-800/80 text-gray-600 dark:text-gray-300 hover:text-rose-500'
                  }`}
                  title="Save to wishlist"
                >
                  <Heart className={`w-4 h-4 ${isWishlisted(product.id) ? 'fill-current' : ''}`} />
                </button>

                <div>
                  <div className="relative aspect-square rounded-xl overflow-hidden bg-gray-100 dark:bg-gray-800 mb-3">
                    <img
                      src={product.image}
                      alt={product.name}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                    />
                    {savings > 0 && (
                      <span className="absolute bottom-2 left-2 px-2 py-0.5 rounded-md text-[10px] font-black bg-rose-600 text-white shadow-md">
                        Save ${savings.toFixed(2)}
                      </span>
                    )}
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>{product.category_name || product.category || 'Featured'}</span>
                      <div className="flex items-center gap-1 text-amber-500 font-bold">
                        <Star className="w-3 h-3 fill-current" />
                        <span>{product.rating || 4.8}</span>
                      </div>
                    </div>

                    <Link to={`/products/${product.id}`}>
                      <h3 className="font-bold text-sm text-gray-900 dark:text-white line-clamp-2 hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                        {product.name}
                      </h3>
                    </Link>
                  </div>
                </div>

                <div className="pt-4 border-t border-gray-100 dark:border-gray-800 mt-4 space-y-3">
                  <div className="flex items-baseline gap-2">
                    <span className="text-lg font-black text-gray-900 dark:text-white">
                      ${currentPrice.toFixed(2)}
                    </span>
                    {originalPrice && (
                      <span className="text-xs text-gray-400 line-through">
                        ${originalPrice.toFixed(2)}
                      </span>
                    )}
                  </div>

                  <button
                    onClick={() => handleAddToCart(product)}
                    className="w-full py-2.5 rounded-xl bg-gray-900 hover:bg-brand-600 text-white dark:bg-white dark:text-gray-900 dark:hover:bg-brand-600 dark:hover:text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-xs"
                  >
                    <ShoppingCart className="w-3.5 h-3.5" /> Add to Cart
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* 4. Trending Catalog Showcase */}
      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
              Trending Products
            </h2>
            <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400 mt-0.5">
              Customer favorites with authentic buyer reviews
            </p>
          </div>
          <Link
            to="/products"
            className="text-xs font-semibold text-brand-600 dark:text-brand-400 hover:underline flex items-center gap-1"
          >
            Browse All ({trending.length}) <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {trending.map((product) => {
            const price = product.discount_price || product.price;
            return (
              <div
                key={product.id}
                className="group p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 hover:shadow-xl transition-all duration-300 flex flex-col justify-between"
              >
                <div className="relative aspect-4/3 rounded-2xl overflow-hidden bg-gray-100 dark:bg-gray-800 mb-4">
                  <img
                    src={product.image}
                    alt={product.name}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                  />
                  <button
                    onClick={() => toggleWishlist(product)}
                    className={`absolute top-3 right-3 p-2 rounded-full backdrop-blur-md transition-colors ${
                      isWishlisted(product.id) 
                        ? 'bg-rose-500 text-white' 
                        : 'bg-white/80 dark:bg-gray-800/80 text-gray-600 dark:text-gray-300 hover:text-rose-500'
                    }`}
                  >
                    <Heart className={`w-4 h-4 ${isWishlisted(product.id) ? 'fill-current' : ''}`} />
                  </button>
                </div>

                <div className="space-y-2 flex-1 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>{product.category_name || product.category || 'Product'}</span>
                      <div className="flex items-center gap-1 text-amber-500 font-bold">
                        <Star className="w-3 h-3 fill-current" />
                        <span>{product.rating || 4.8}</span>
                      </div>
                    </div>
                    <Link to={`/products/${product.id}`}>
                      <h3 className="font-bold text-sm text-gray-900 dark:text-white line-clamp-2 hover:text-brand-600 transition-colors mt-1">
                        {product.name}
                      </h3>
                    </Link>
                  </div>

                  <div className="pt-3 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between">
                    <span className="text-base font-black text-gray-900 dark:text-white">
                      ${price.toFixed(2)}
                    </span>
                    <button
                      onClick={() => handleAddToCart(product)}
                      className="p-2.5 rounded-xl bg-gray-900 hover:bg-brand-600 text-white dark:bg-white dark:text-gray-900 dark:hover:bg-brand-600 dark:hover:text-white transition-colors"
                      title="Add to Cart"
                    >
                      <ShoppingCart className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

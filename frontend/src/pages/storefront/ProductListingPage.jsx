import { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { demoProducts } from './HomePage';
import { productService } from '../../services/api';
import { useCart } from '../../context/CartContext';
import { useWishlist } from '../../context/WishlistContext';
import { 
  Star, ShoppingCart, Heart, Filter, SlidersHorizontal, 
  ChevronDown, ChevronLeft, ChevronRight, X, Check, Loader2 
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function ProductListingPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const categoryParam = searchParams.get('category') || 'All';
  const queryParam = searchParams.get('q') || '';
  const badgeParam = searchParams.get('badge') || '';
  const initialPage = parseInt(searchParams.get('page') || '1', 10);

  const [categories, setCategories] = useState([]);
  const [products, setProducts] = useState(demoProducts);
  const [totalProducts, setTotalProducts] = useState(demoProducts.length);
  const [totalPages, setTotalPages] = useState(1);
  const [currentPage, setCurrentPage] = useState(initialPage);
  const [selectedSort, setSelectedSort] = useState('popular');
  const [inStockOnly, setInStockOnly] = useState(false);
  const [priceRange, setPriceRange] = useState('all');
  const [mobileFilterOpen, setMobileFilterOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { addToCart } = useCart();
  const { isWishlisted, toggleWishlist } = useWishlist();

  // Fetch categories on mount
  useEffect(() => {
    productService.getCategories().then((cats) => {
      if (cats && cats.length > 0) setCategories(cats);
    }).catch((e) => console.warn('Could not fetch categories:', e));
  }, []);

  // Fetch products whenever filters or page changes
  useEffect(() => {
    let isMounted = true;
    async function loadProducts() {
      setIsLoading(true);
      try {
        const params = {
          page: currentPage,
          limit: 9,
          sort: selectedSort,
        };

        if (categoryParam && categoryParam !== 'All') {
          params.category = categoryParam;
        }
        if (queryParam) {
          params.q = queryParam;
        }
        if (badgeParam) {
          params.badge = badgeParam;
        }
        if (inStockOnly) {
          params.in_stock = 'true';
        }

        if (priceRange === 'under50') {
          params.max_price = 50;
        } else if (priceRange === '50to150') {
          params.min_price = 50;
          params.max_price = 150;
        } else if (priceRange === '150to300') {
          params.min_price = 150;
          params.max_price = 300;
        } else if (priceRange === 'over300') {
          params.min_price = 300;
        }

        const res = await productService.getProducts(params);
        if (isMounted && res) {
          setProducts(res.products || []);
          setTotalProducts(res.total || 0);
          setTotalPages(res.total_pages || 1);
        }
      } catch (err) {
        console.warn('Fallback to client filter:', err);
        // Client fallback filter if offline
        let filtered = [...demoProducts];
        if (categoryParam !== 'All') {
          filtered = filtered.filter(p => p.category.toLowerCase().includes(categoryParam.toLowerCase()));
        }
        if (queryParam) {
          filtered = filtered.filter(p => p.name.toLowerCase().includes(queryParam.toLowerCase()));
        }
        if (badgeParam === 'deal') {
          filtered = filtered.filter(p => p.discount_price);
        }
        if (inStockOnly) {
          filtered = filtered.filter(p => p.inStock);
        }
        setProducts(filtered);
        setTotalProducts(filtered.length);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadProducts();
    return () => { isMounted = false; };
  }, [categoryParam, queryParam, badgeParam, selectedSort, priceRange, inStockOnly, currentPage]);

  const handleCategoryChange = (catName) => {
    const nextParams = new URLSearchParams(searchParams);
    if (catName === 'All') {
      nextParams.delete('category');
    } else {
      nextParams.set('category', catName);
    }
    nextParams.set('page', '1');
    setCurrentPage(1);
    setSearchParams(nextParams);
    setMobileFilterOpen(false);
  };

  const handleResetFilters = () => {
    setSearchParams({});
    setCurrentPage(1);
    setPriceRange('all');
    setInStockOnly(false);
    setSelectedSort('popular');
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Page Header & Breadcrumbs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-gray-200 dark:border-gray-800">
        <div>
          <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
            <Link to="/" className="hover:underline">Home</Link> / <span>Products</span>
            {categoryParam !== 'All' && <span> / <strong className="text-gray-900 dark:text-white">{categoryParam}</strong></span>}
          </div>
          <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">
            {queryParam ? `Search results for "${queryParam}"` : (categoryParam === 'All' ? 'All Products Catalog' : `${categoryParam} Collection`)}
          </h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Showing {products.length} of {totalProducts} verified items
          </p>
        </div>

        {/* Filter Trigger (Mobile) & Sort Selector */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileFilterOpen(true)}
            className="lg:hidden px-3.5 py-2 rounded-xl border border-gray-300 dark:border-gray-700 text-xs font-semibold flex items-center gap-2"
          >
            <SlidersHorizontal className="w-3.5 h-3.5" /> Filters
          </button>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-gray-500 whitespace-nowrap">Sort by:</span>
            <select
              value={selectedSort}
              onChange={(e) => setSelectedSort(e.target.value)}
              className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-xl px-3 py-2 font-semibold text-gray-800 dark:text-gray-200 focus:outline-none"
            >
              <option value="popular">Most Popular</option>
              <option value="price_asc">Price: Low to High</option>
              <option value="price_desc">Price: High to Low</option>
              <option value="newest">Newest Arrivals</option>
              <option value="name_asc">Name: A to Z</option>
            </select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Filter Sidebar (Desktop & Mobile Drawer) */}
        <div className={`fixed inset-0 z-50 lg:static lg:z-auto bg-black/60 lg:bg-transparent transition-opacity ${
          mobileFilterOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none lg:opacity-100 lg:pointer-events-auto'
        }`}>
          <div className={`w-80 max-w-[85vw] lg:w-full h-full lg:h-auto bg-white dark:bg-gray-900 p-6 lg:p-0 overflow-y-auto space-y-6 transition-transform duration-300 ${
            mobileFilterOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
          }`}>
            <div className="flex items-center justify-between lg:hidden pb-3 border-b border-gray-200 dark:border-gray-800">
              <span className="font-bold text-base">Filter Catalog</span>
              <button onClick={() => setMobileFilterOpen(false)} className="p-1 text-gray-500">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Categories Filter */}
            <div className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-3">
              <div className="flex items-center justify-between font-bold text-sm text-gray-900 dark:text-white">
                <span className="flex items-center gap-2"><Filter className="w-4 h-4 text-brand-600" /> Categories</span>
              </div>
              <div className="space-y-1">
                <button
                  onClick={() => handleCategoryChange('All')}
                  className={`w-full text-left px-3 py-2 rounded-xl text-xs font-semibold transition-colors flex items-center justify-between ${
                    categoryParam === 'All'
                      ? 'bg-brand-50 text-brand-700 dark:bg-brand-950/50 dark:text-brand-300'
                      : 'text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800/50'
                  }`}
                >
                  <span>All Categories</span>
                  <span className="text-[10px] text-gray-400 font-normal">{totalProducts}</span>
                </button>
                {categories.map((cat) => (
                  <button
                    key={cat.id || cat.slug}
                    onClick={() => handleCategoryChange(cat.name)}
                    className={`w-full text-left px-3 py-2 rounded-xl text-xs font-semibold transition-colors flex items-center justify-between ${
                      categoryParam.toLowerCase() === cat.name.toLowerCase()
                        ? 'bg-brand-50 text-brand-700 dark:bg-brand-950/50 dark:text-brand-300'
                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800/50'
                    }`}
                  >
                    <span>{cat.name}</span>
                    <span className="text-[10px] text-gray-400 font-normal">{cat.product_count || ''}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Price Range Filter */}
            <div className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-3">
              <span className="font-bold text-sm text-gray-900 dark:text-white block">Price Range</span>
              <div className="space-y-2 text-xs">
                {[
                  { id: 'all', label: 'All Prices' },
                  { id: 'under50', label: 'Under $50' },
                  { id: '50to150', label: '$50 to $150' },
                  { id: '150to300', label: '$150 to $300' },
                  { id: 'over300', label: '$300 & Above' },
                ].map((item) => (
                  <label key={item.id} className="flex items-center gap-2 cursor-pointer text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
                    <input
                      type="radio"
                      name="price_filter"
                      checked={priceRange === item.id}
                      onChange={() => { setPriceRange(item.id); setCurrentPage(1); }}
                      className="text-brand-600"
                    />
                    <span>{item.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Availability Filter */}
            <div className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-3">
              <span className="font-bold text-sm text-gray-900 dark:text-white block">Availability</span>
              <label className="flex items-center gap-2 cursor-pointer text-xs text-gray-600 dark:text-gray-400">
                <input
                  type="checkbox"
                  checked={inStockOnly}
                  onChange={(e) => { setInStockOnly(e.target.checked); setCurrentPage(1); }}
                  className="rounded text-brand-600"
                />
                <span>In Stock Only</span>
              </label>
            </div>

            {/* Reset Filter Button */}
            <button
              onClick={handleResetFilters}
              className="w-full py-2.5 px-4 rounded-xl border border-gray-200 dark:border-gray-800 text-xs font-semibold text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-center"
            >
              Reset All Filters
            </button>
          </div>
        </div>

        {/* Product Cards Grid */}
        <div className="lg:col-span-3 space-y-8">
          {isLoading ? (
            <div className="p-16 text-center rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 flex flex-col items-center justify-center space-y-3">
              <Loader2 className="w-8 h-8 text-brand-600 animate-spin" />
              <p className="text-xs text-gray-500">Updating product catalog...</p>
            </div>
          ) : products.length === 0 ? (
            <div className="p-12 text-center rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-3">
              <p className="text-base font-bold text-gray-900 dark:text-white">No products found</p>
              <p className="text-xs text-gray-500 max-w-sm mx-auto">
                No catalog items match your current filter selection. Try changing the category or reset your price filters.
              </p>
              <button
                onClick={handleResetFilters}
                className="mt-3 px-5 py-2.5 bg-brand-600 text-white rounded-xl text-xs font-semibold"
              >
                Clear Filters
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-6">
              {products.map((prod) => {
                const currentPrice = prod.discount_price || prod.price;
                const originalPrice = prod.discount_price ? prod.price : null;

                return (
                  <div
                    key={prod.id}
                    className="group rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 p-4 hover:shadow-xl transition-all duration-300 flex flex-col justify-between"
                  >
                    <div className="relative aspect-square rounded-2xl bg-gray-100 dark:bg-gray-800 overflow-hidden mb-4">
                      <img
                        src={prod.image}
                        alt={prod.name}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                      />
                      {prod.badge && (
                        <span className="absolute top-3 left-3 px-2 py-0.5 rounded-md text-[10px] font-black bg-rose-600 text-white shadow-md">
                          {prod.badge}
                        </span>
                      )}
                      <button
                        onClick={() => toggleWishlist(prod)}
                        className={`absolute top-3 right-3 p-2 rounded-full backdrop-blur-md transition-colors ${
                          isWishlisted(prod.id)
                            ? 'bg-rose-500 text-white'
                            : 'bg-white/80 dark:bg-gray-800/80 text-gray-600 dark:text-gray-300 hover:text-rose-500'
                        }`}
                        title="Wishlist"
                      >
                        <Heart className={`w-3.5 h-3.5 ${isWishlisted(prod.id) ? 'fill-current' : ''}`} />
                      </button>
                    </div>

                    <div className="space-y-2 flex-1 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <span>{prod.category_name || prod.category || 'General'}</span>
                          <div className="flex items-center gap-1 text-amber-500 font-bold">
                            <Star className="w-3.5 h-3.5 fill-current" />
                            <span>{prod.rating || 4.8}</span>
                          </div>
                        </div>

                        <Link to={`/products/${prod.id}`}>
                          <h3 className="font-bold text-sm text-gray-900 dark:text-white line-clamp-2 hover:text-brand-600 transition-colors mt-1">
                            {prod.name}
                          </h3>
                        </Link>
                      </div>

                      <div className="pt-3 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between">
                        <div className="flex items-baseline gap-2">
                          <span className="text-base font-black text-gray-900 dark:text-white">
                            ${currentPrice.toFixed(2)}
                          </span>
                          {originalPrice && (
                            <span className="text-xs text-gray-400 line-through">
                              ${originalPrice.toFixed(2)}
                            </span>
                          )}
                        </div>

                        <button
                          onClick={() => addToCart(prod, 1)}
                          className="p-2.5 rounded-xl bg-gray-900 text-white dark:bg-white dark:text-gray-900 hover:bg-brand-600 dark:hover:bg-brand-600 dark:hover:text-white transition-colors"
                          title="Add to cart"
                        >
                          <ShoppingCart className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-6 border-t border-gray-200 dark:border-gray-800">
              <button
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                className="px-4 py-2 rounded-xl border border-gray-200 dark:border-gray-800 text-xs font-semibold flex items-center gap-1 text-gray-600 dark:text-gray-300 disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" /> Previous
              </button>

              <span className="text-xs font-medium text-gray-500">
                Page <strong className="text-gray-900 dark:text-white">{currentPage}</strong> of {totalPages}
              </span>

              <button
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                className="px-4 py-2 rounded-xl border border-gray-200 dark:border-gray-800 text-xs font-semibold flex items-center gap-1 text-gray-600 dark:text-gray-300 disabled:opacity-40"
              >
                Next <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

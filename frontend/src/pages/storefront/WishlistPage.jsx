import { Link } from 'react-router-dom';
import { useWishlist } from '../../context/WishlistContext';
import { Heart, ShoppingCart, Trash2, ArrowRight, Loader2, PackageCheck } from 'lucide-react';

export default function WishlistPage() {
  const { items, moveToCart, removeFromWishlist, isLoading } = useWishlist();

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Page Header */}
      <div className="flex items-center justify-between pb-4 border-b border-gray-200 dark:border-gray-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <Heart className="w-6 h-6 text-rose-500 fill-current shrink-0" /> 
            My Saved Items ({items.length})
          </h1>
          <p className="text-xs text-gray-500 mt-1">Products you've saved to purchase later or monitor for price drops</p>
        </div>

        {items.length > 0 && (
          <Link
            to="/products"
            className="text-xs text-brand-600 font-semibold hover:underline hidden sm:inline-block"
          >
            Explore More Items
          </Link>
        )}
      </div>

      {isLoading && items.length === 0 ? (
        <div className="py-20 text-center flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-brand-600 animate-spin" />
          <p className="text-xs text-gray-500">Retrieving saved wishlist items...</p>
        </div>
      ) : items.length === 0 ? (
        <div className="text-center py-16 px-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4 shadow-xs">
          <div className="w-16 h-16 rounded-full bg-rose-50 dark:bg-rose-950/40 text-rose-500 flex items-center justify-center mx-auto">
            <Heart className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Your wishlist is currently empty</h2>
          <p className="text-xs sm:text-sm text-gray-500 max-w-sm mx-auto">
            Save products you like by clicking the heart icon on any card in the store catalog.
          </p>
          <Link
            to="/products"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs transition-colors shadow-md shadow-brand-600/20"
          >
            Explore Catalog <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {items.map((item) => (
            <div
              key={item.id || item.product_id}
              className="group p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 flex flex-col justify-between space-y-4 shadow-xs hover:shadow-xl transition-all duration-300"
            >
              <div className="relative aspect-square rounded-2xl overflow-hidden bg-gray-100 dark:bg-gray-800">
                <img
                  src={item.image}
                  alt={item.name}
                  className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                />
                <button
                  onClick={() => removeFromWishlist(item.product_id || item.id)}
                  className="absolute top-3 right-3 p-2 rounded-full bg-white/90 dark:bg-gray-800/90 text-rose-500 hover:bg-rose-500 hover:text-white transition-colors shadow-sm"
                  title="Remove from wishlist"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-1.5 flex-1 flex flex-col justify-between">
                <div>
                  <span className="text-[11px] font-semibold text-gray-500 block">
                    {item.category || 'General'}
                  </span>
                  <Link to={`/products/${item.product_id || item.id}`}>
                    <h3 className="font-bold text-sm text-gray-900 dark:text-white line-clamp-2 hover:text-brand-600 transition-colors mt-0.5">
                      {item.name}
                    </h3>
                  </Link>
                </div>

                <div className="flex items-baseline gap-2 pt-1">
                  <span className="text-base font-black text-gray-900 dark:text-white">
                    ${Number(item.price).toFixed(2)}
                  </span>
                  {item.original_price && (
                    <span className="text-xs text-gray-400 line-through">
                      ${Number(item.original_price).toFixed(2)}
                    </span>
                  )}
                </div>
              </div>

              <div className="pt-3 border-t border-gray-100 dark:border-gray-800">
                <button
                  onClick={() => moveToCart(item)}
                  className="w-full py-2.5 px-4 rounded-xl bg-gray-900 text-white dark:bg-white dark:text-gray-900 hover:bg-brand-600 dark:hover:bg-brand-600 dark:hover:text-white font-bold text-xs flex items-center justify-center gap-2 transition-colors shadow-xs"
                >
                  <ShoppingCart className="w-3.5 h-3.5" /> Move to Cart
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useCart } from '../../context/CartContext';
import { 
  Trash2, ArrowRight, ShieldCheck, ShoppingBag, 
  Tag, CheckCircle2, Truck, AlertTriangle, ArrowLeft,
  TicketPercent, Sparkles, Check, Copy, ChevronDown, ChevronUp
} from 'lucide-react';
import toast from 'react-hot-toast';
import { couponService } from '../../services/api';
import { cn } from '../../utils/helpers';

export default function CartPage() {
  const { 
    items, totalItems, subtotal, shippingFee, total, 
    amountForFreeShipping, updateQuantity, removeFromCart, 
    clearCart, isLoading 
  } = useCart();

  const [couponCode, setCouponCode] = useState('');
  const [appliedCoupon, setAppliedCoupon] = useState(null);
  const [couponDiscount, setCouponDiscount] = useState(0);
  const [isValidatingCoupon, setIsValidatingCoupon] = useState(false);
  const [availableCoupons, setAvailableCoupons] = useState([]);
  const [showCouponsList, setShowCouponsList] = useState(true);

  useEffect(() => {
    const loadCoupons = async () => {
      try {
        const list = await couponService.getAvailableCoupons();
        setAvailableCoupons(list || []);
      } catch (err) {
        console.error('Failed to load coupons:', err);
      }
    };
    loadCoupons();
  }, []);

  const handleApplyCoupon = async (e, codeOverride = null) => {
    if (e) e.preventDefault();
    const code = (codeOverride || couponCode).trim().toUpperCase();
    if (!code) return;

    try {
      setIsValidatingCoupon(true);
      const res = await couponService.validateCoupon(code, subtotal);
      if (res.valid) {
        setAppliedCoupon({ 
          code: res.code, 
          discount: res.discount_amount,
          type: res.discount_type,
          value: res.discount_value 
        });
        setCouponDiscount(res.discount_amount);
        toast.success(res.message || `Coupon ${res.code} applied!`);
        setCouponCode('');
      }
    } catch (err) {
      const msg = err.response?.data?.error || 'Invalid or ineligible coupon code';
      toast.error(msg);
    } finally {
      setIsValidatingCoupon(false);
    }
  };

  const handleRemoveCoupon = () => {
    setAppliedCoupon(null);
    setCouponDiscount(0);
    toast.success('Coupon removed');
  };

  const finalTotal = Math.max(0, total - couponDiscount);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-gray-200 dark:border-gray-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">
            Shopping Cart ({totalItems} {totalItems === 1 ? 'item' : 'items'})
          </h1>
          <p className="text-xs text-gray-500 mt-1">Review your selected items, apply promotional codes, and proceed to secure checkout</p>
        </div>

        {items.length > 0 && (
          <button
            onClick={() => {
              if (window.confirm('Clear all items from your shopping cart?')) {
                clearCart();
              }
            }}
            className="text-xs text-rose-500 hover:text-rose-600 font-semibold w-fit"
          >
            Clear Shopping Cart
          </button>
        )}
      </div>

      {/* Free Shipping Progress Indicator */}
      {items.length > 0 && (
        <div className="p-4 rounded-2xl bg-brand-50 dark:bg-brand-950/40 border border-brand-200/60 dark:border-brand-800/40 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-brand-900 dark:text-brand-200 font-medium">
            <Truck className="w-4 h-4 text-brand-600 dark:text-brand-400 shrink-0" />
            {amountForFreeShipping > 0 ? (
              <span>
                Add <strong className="text-brand-700 dark:text-brand-300">${amountForFreeShipping.toFixed(2)}</strong> more of eligible items to unlock <strong className="text-emerald-600">FREE Shipping</strong>!
              </span>
            ) : (
              <span className="text-emerald-600 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> You've unlocked FREE standard shipping!
              </span>
            )}
          </div>
        </div>
      )}

      {items.length === 0 ? (
        <div className="text-center py-16 px-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4 shadow-xs">
          <div className="w-16 h-16 rounded-full bg-brand-50 dark:bg-brand-950/50 text-brand-600 flex items-center justify-center mx-auto">
            <ShoppingBag className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Your cart is currently empty</h2>
          <p className="text-xs sm:text-sm text-gray-500 max-w-sm mx-auto">
            Explore our curated catalog and discover premium technology, lifestyle essentials, and designer apparel.
          </p>
          <Link
            to="/products"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs transition-colors shadow-md shadow-brand-600/20"
          >
            Start Shopping <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Cart Items List */}
          <div className="lg:col-span-2 space-y-4">
            {items.map((item) => (
              <div
                key={item.id}
                className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 flex flex-col sm:flex-row items-center gap-4 shadow-xs"
              >
                <img
                  src={item.image}
                  alt={item.name}
                  className="w-20 h-20 sm:w-24 sm:h-24 rounded-2xl object-cover shrink-0 bg-gray-100 dark:bg-gray-800"
                />

                <div className="flex-1 space-y-1 text-center sm:text-left">
                  <Link to={`/products/${item.product_id}`}>
                    <h3 className="font-bold text-sm text-gray-900 dark:text-white hover:text-brand-600 transition-colors line-clamp-2">
                      {item.name}
                    </h3>
                  </Link>

                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2 text-xs text-gray-500">
                    <span>Unit: <strong>${item.unit_price.toFixed(2)}</strong></span>
                    {item.regular_price > item.unit_price && (
                      <span className="line-through text-gray-400">${item.regular_price.toFixed(2)}</span>
                    )}
                  </div>

                  {item.is_out_of_stock && (
                    <div className="text-[11px] font-bold text-rose-500 flex items-center justify-center sm:justify-start gap-1">
                      <AlertTriangle className="w-3 h-3" /> Quantity exceeds available inventory
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-4">
                  {/* Quantity Stepper */}
                  <div className="flex items-center border border-gray-300 dark:border-gray-700 rounded-xl overflow-hidden bg-gray-50 dark:bg-gray-800">
                    <button
                      onClick={() => updateQuantity(item.id, item.quantity - 1)}
                      className="px-3 py-1.5 text-xs font-bold hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                      title="Decrease quantity"
                    >
                      -
                    </button>
                    <span className="px-3 py-1.5 text-xs font-semibold">{item.quantity}</span>
                    <button
                      onClick={() => updateQuantity(item.id, item.quantity + 1)}
                      className="px-3 py-1.5 text-xs font-bold hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                      title="Increase quantity"
                    >
                      +
                    </button>
                  </div>

                  {/* Line Total */}
                  <div className="text-right min-w-[70px]">
                    <span className="text-sm font-black text-gray-900 dark:text-white block">
                      ${item.total_price.toFixed(2)}
                    </span>
                  </div>

                  {/* Remove Button */}
                  <button
                    onClick={() => removeFromCart(item.id)}
                    className="p-2 text-gray-400 hover:text-rose-500 transition-colors rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30"
                    title="Remove item"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}

            <Link
              to="/products"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-500 hover:text-brand-600 transition-colors pt-2"
            >
              <ArrowLeft className="w-4 h-4" /> Continue Shopping
            </Link>
          </div>

          {/* Order Summary Box */}
          <div className="space-y-4">
            <div className="p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-5 shadow-md">
              <h2 className="text-lg font-black text-gray-900 dark:text-white">
                Order Summary
              </h2>

              <div className="space-y-3 text-xs">
                <div className="flex justify-between text-gray-600 dark:text-gray-400">
                  <span>Subtotal ({totalItems} items)</span>
                  <span className="font-semibold text-gray-900 dark:text-white">${subtotal.toFixed(2)}</span>
                </div>

                <div className="flex justify-between text-gray-600 dark:text-gray-400">
                  <span>Standard Shipping</span>
                  <span className="font-semibold">
                    {shippingFee === 0 ? (
                      <span className="text-emerald-600 font-bold">FREE</span>
                    ) : (
                      `$${shippingFee.toFixed(2)}`
                    )}
                  </span>
                </div>

                {appliedCoupon && (
                  <div className="flex justify-between text-emerald-600 font-medium">
                    <span className="flex items-center gap-1">
                      Coupon ({appliedCoupon.code})
                      <button onClick={handleRemoveCoupon} className="text-gray-400 hover:text-rose-500 ml-1">×</button>
                    </span>
                    <span>-${couponDiscount.toFixed(2)}</span>
                  </div>
                )}

                <div className="pt-3 border-t border-gray-200 dark:border-gray-800 flex justify-between text-base font-black text-gray-900 dark:text-white">
                  <span>Estimated Total</span>
                  <span>${finalTotal.toFixed(2)}</span>
                </div>
              </div>

              {/* Promo Coupon Form */}
              <form onSubmit={handleApplyCoupon} className="pt-2">
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-[11px] font-bold text-gray-600 dark:text-gray-400">
                    Promotional Coupon Code
                  </label>
                  {availableCoupons.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setShowCouponsList(!showCouponsList)}
                      className="text-[10px] font-bold text-brand-600 dark:text-brand-400 hover:underline flex items-center gap-0.5"
                    >
                      <span>{showCouponsList ? 'Hide Offers' : `View Offers (${availableCoupons.length})`}</span>
                      {showCouponsList ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                  )}
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="e.g. SAVE10"
                    value={couponCode}
                    onChange={(e) => setCouponCode(e.target.value)}
                    className="flex-1 px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white uppercase font-mono focus:outline-none focus:border-brand-500"
                  />
                  <button
                    type="submit"
                    disabled={isValidatingCoupon}
                    className="px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-gray-900 rounded-xl text-xs font-bold hover:bg-brand-600 dark:hover:bg-brand-600 dark:hover:text-white transition-colors disabled:opacity-50"
                  >
                    {isValidatingCoupon ? 'Checking...' : 'Apply'}
                  </button>
                </div>
              </form>

              {/* Available Coupons Drawer/List */}
              {availableCoupons.length > 0 && showCouponsList && (
                <div className="space-y-2 pt-1">
                  <div className="text-[11px] font-bold text-gray-500 flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-amber-500" />
                    <span>Available Offers</span>
                  </div>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {availableCoupons.map((c) => {
                      const isApplied = appliedCoupon?.code === c.code;
                      const qualifies = subtotal >= c.min_order_value;
                      const diff = (c.min_order_value - subtotal).toFixed(2);

                      return (
                        <div
                          key={c.id}
                          className={cn(
                            "p-2.5 rounded-xl border transition-all text-xs flex items-center justify-between gap-2",
                            isApplied 
                              ? "border-emerald-500 bg-emerald-50/50 dark:bg-emerald-950/20" 
                              : "border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/40 hover:border-gray-300"
                          )}
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono font-black text-gray-900 dark:text-white text-[11px] px-1.5 py-0.5 rounded bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700">
                                {c.code}
                              </span>
                              <span className="font-bold text-[10px] text-brand-600 dark:text-brand-400">
                                {c.badge}
                              </span>
                            </div>
                            <p className="text-[10px] text-gray-500 mt-1 truncate">
                              {c.description}
                            </p>
                            {!qualifies && (
                              <p className="text-[9px] text-amber-600 dark:text-amber-400 mt-0.5 font-medium">
                                Add ${diff} more to qualify
                              </p>
                            )}
                          </div>

                          <div>
                            {isApplied ? (
                              <span className="text-[10px] font-bold text-emerald-600 flex items-center gap-0.5">
                                <Check className="w-3 h-3" /> Applied
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handleApplyCoupon(null, c.code)}
                                disabled={!qualifies || isValidatingCoupon}
                                className={cn(
                                  "px-2.5 py-1 rounded-lg text-[10px] font-bold transition-colors cursor-pointer",
                                  qualifies 
                                    ? "bg-brand-600 text-white hover:bg-brand-700" 
                                    : "bg-gray-200 dark:bg-gray-700 text-gray-400 cursor-not-allowed"
                                )}
                              >
                                Apply
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Checkout Button */}
              <Link
                to="/checkout"
                className="w-full py-3.5 rounded-2xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-brand-600/30 transition-all text-center"
              >
                Proceed to Checkout <ArrowRight className="w-4 h-4" />
              </Link>

              <div className="flex items-center gap-2 text-[11px] text-gray-500 justify-center">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                <span>Safe 256-Bit Encrypted Checkout</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

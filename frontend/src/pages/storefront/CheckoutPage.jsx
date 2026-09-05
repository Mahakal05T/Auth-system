import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useCart } from '../../context/CartContext';
import { useAuth } from '../../context/AuthContext';
import { addressService, checkoutService, couponService } from '../../services/api';
import { 
  ShieldCheck, CheckCircle2, CreditCard, Banknote, 
  ArrowRight, MapPin, Plus, Loader2, Check, Tag, AlertTriangle,
  Sparkles, ChevronDown, ChevronUp, TicketPercent 
} from 'lucide-react';
import toast from 'react-hot-toast';
import { cn } from '../../utils/helpers';

export default function CheckoutPage() {
  const navigate = useNavigate();
  const { user, isAuthenticated } = useAuth();
  const { items, totalItems, subtotal, shippingFee, clearCart } = useCart();

  // Addresses
  const [savedAddresses, setSavedAddresses] = useState([]);
  const [selectedAddressId, setSelectedAddressId] = useState('new');
  const [isLoadingAddresses, setIsLoadingAddresses] = useState(false);

  // New Address Form fields (used if selectedAddressId === 'new')
  const [fullName, setFullName] = useState(user?.name || '');
  const [phone, setPhone] = useState(user?.phone || '');
  const [streetAddress, setStreetAddress] = useState('');
  const [city, setCity] = useState('');
  const [state, setState] = useState('');
  const [postalCode, setPostalCode] = useState('');
  const [country, setCountry] = useState('USA');

  // Coupon state
  const [couponCode, setCouponCode] = useState('');
  const [appliedCoupon, setAppliedCoupon] = useState(null);
  const [couponDiscount, setCouponDiscount] = useState(0);
  const [isValidatingCoupon, setIsValidatingCoupon] = useState(false);
  const [availableCoupons, setAvailableCoupons] = useState([]);
  const [showCouponsList, setShowCouponsList] = useState(true);

  const [paymentMethod, setPaymentMethod] = useState('cod');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    couponService.getAvailableCoupons()
      .then(list => setAvailableCoupons(list || []))
      .catch(err => console.warn('Could not load available coupons:', err));
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      setIsLoadingAddresses(true);
      addressService.getAddresses()
        .then((addrs) => {
          setSavedAddresses(addrs);
          const defaultAddr = addrs.find(a => a.is_default);
          if (defaultAddr) {
            setSelectedAddressId(defaultAddr.id);
          } else if (addrs.length > 0) {
            setSelectedAddressId(addrs[0].id);
          } else {
            setSelectedAddressId('new');
          }
        })
        .catch((err) => console.warn('Could not load saved addresses:', err))
        .finally(() => setIsLoadingAddresses(false));
    }
  }, [isAuthenticated]);

  const handleApplyCoupon = async (e, codeOverride = null) => {
    if (e) e.preventDefault();
    const code = (codeOverride || couponCode).trim().toUpperCase();
    if (!code) return;

    if (!isAuthenticated) {
      toast.error('Please sign in to apply promotional vouchers');
      return;
    }

    try {
      setIsValidatingCoupon(true);
      const res = await checkoutService.validateCoupon(code, subtotal);
      if (res.valid) {
        setAppliedCoupon({ code: res.code, discount: res.discount_amount });
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

  const finalTotal = Math.max(0, subtotal - couponDiscount) + shippingFee;

  const handleSubmitOrder = async (e) => {
    e.preventDefault();

    if (!isAuthenticated) {
      toast.error('Please sign in to complete your purchase');
      navigate('/login?redirect=/checkout');
      return;
    }

    if (items.length === 0) {
      toast.error('Your cart is empty. Add products before checking out.');
      return;
    }

    const payload = {
      payment_method: paymentMethod === 'mock_card' ? 'CARD' : 'COD',
      coupon_code: appliedCoupon?.code || null
    };

    if (selectedAddressId === 'new') {
      if (!fullName || !phone || !streetAddress || !city || !postalCode) {
        toast.error('Please complete all required shipping fields');
        return;
      }
      payload.address_data = {
        full_name: fullName,
        phone: phone,
        street_address: streetAddress,
        city: city,
        state: state,
        postal_code: postalCode,
        country: country
      };
    } else {
      payload.address_id = selectedAddressId;
    }

    try {
      setIsSubmitting(true);
      const res = await checkoutService.placeOrder(payload);
      if (res.success && res.order) {
        toast.success(`Order #${res.order.order_number} confirmed! 🎉`, { duration: 5000 });
        clearCart();
        navigate('/orders', { state: { confirmedOrder: res.order } });
      }
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to place order. Please try again.';
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-in fade-in duration-300">
      <div className="pb-4 border-b border-gray-200 dark:border-gray-800">
        <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">Secure Checkout</h1>
        <p className="text-xs sm:text-sm text-gray-500 mt-1">
          Review shipping destination, verify line items, and select payment method
        </p>
      </div>

      <form onSubmit={handleSubmitOrder} className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Shipping & Payment Form */}
        <div className="lg:col-span-2 space-y-6">
          {/* Shipping Address Section */}
          <div className="p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-5 shadow-xs">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-brand-600 text-white text-xs flex items-center justify-center font-bold">1</span>
                Shipping Address
              </h2>
              {isAuthenticated && (
                <Link to="/account" className="text-xs text-brand-600 font-semibold hover:underline">
                  Manage Addresses
                </Link>
              )}
            </div>

            {/* Saved Addresses Picker */}
            {savedAddresses.length > 0 && (
              <div className="space-y-3">
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300">
                  Select a saved delivery address:
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {savedAddresses.map((addr) => (
                    <label
                      key={addr.id}
                      onClick={() => setSelectedAddressId(addr.id)}
                      className={`p-4 rounded-2xl border cursor-pointer flex flex-col justify-between transition-all ${
                        selectedAddressId === addr.id
                          ? 'border-brand-600 bg-brand-50/40 dark:bg-brand-950/40 ring-2 ring-brand-600/20'
                          : 'border-gray-200 dark:border-gray-800 hover:border-gray-300'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <span className="font-bold text-xs text-gray-900 dark:text-white flex items-center gap-1.5">
                          <input
                            type="radio"
                            name="delivery_address"
                            checked={selectedAddressId === addr.id}
                            onChange={() => setSelectedAddressId(addr.id)}
                            className="text-brand-600"
                          />
                          {addr.full_name}
                        </span>
                        {addr.is_default && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-extrabold bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-300">
                            DEFAULT
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-2 line-clamp-2">
                        {addr.street_address}, {addr.city}, {addr.state} {addr.postal_code}
                      </p>
                      <p className="text-[11px] text-gray-500 mt-1 font-mono">{addr.phone}</p>
                    </label>
                  ))}

                  <label
                    onClick={() => setSelectedAddressId('new')}
                    className={`p-4 rounded-2xl border border-dashed cursor-pointer flex items-center justify-center gap-2 transition-all text-xs font-semibold ${
                      selectedAddressId === 'new'
                        ? 'border-brand-600 bg-brand-50/20 dark:bg-brand-950/20 text-brand-600'
                        : 'border-gray-300 dark:border-gray-700 text-gray-500 hover:border-gray-400'
                    }`}
                  >
                    <Plus className="w-4 h-4" /> Deliver to New Address
                  </label>
                </div>
              </div>
            )}

            {/* Custom/New Address Fields */}
            {selectedAddressId === 'new' && (
              <div className="pt-2 border-t border-gray-100 dark:border-gray-800 space-y-4">
                <span className="text-xs font-bold text-gray-800 dark:text-gray-200 block">
                  {savedAddresses.length > 0 ? 'Enter New Address Details' : 'Recipient Details'}
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Full Name *</label>
                    <input
                      type="text"
                      required
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="e.g. John Doe"
                      className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>
                  <div>
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Phone Number *</label>
                    <input
                      type="tel"
                      required
                      value={phone}
                      onChange={(e) => setPhone(e.target.value)}
                      placeholder="+1 (555) 000-0000"
                      className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Street Address *</label>
                    <input
                      type="text"
                      required
                      value={streetAddress}
                      onChange={(e) => setStreetAddress(e.target.value)}
                      placeholder="Apartment, suite, unit, street"
                      className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>
                  <div>
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">City *</label>
                    <input
                      type="text"
                      required
                      value={city}
                      onChange={(e) => setCity(e.target.value)}
                      placeholder="e.g. Springfield"
                      className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>
                  <div>
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">State / Province</label>
                    <input
                      type="text"
                      value={state}
                      onChange={(e) => setState(e.target.value)}
                      placeholder="e.g. OR"
                      className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Postal Code *</label>
                    <input
                      type="text"
                      required
                      value={postalCode}
                      onChange={(e) => setPostalCode(e.target.value)}
                      placeholder="e.g. 97477"
                      className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Payment Method Section */}
          <div className="p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4 shadow-xs">
            <h2 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-brand-600 text-white text-xs flex items-center justify-center font-bold">2</span>
              Payment Method
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label
                onClick={() => setPaymentMethod('cod')}
                className={`p-4 rounded-2xl border cursor-pointer flex items-center gap-3 transition-all ${
                  paymentMethod === 'cod'
                    ? 'border-brand-600 bg-brand-50/50 dark:bg-brand-950/40 ring-2 ring-brand-600/20'
                    : 'border-gray-200 dark:border-gray-800'
                }`}
              >
                <input
                  type="radio"
                  name="payment"
                  checked={paymentMethod === 'cod'}
                  onChange={() => setPaymentMethod('cod')}
                  className="text-brand-600"
                />
                <Banknote className="w-5 h-5 text-emerald-600 shrink-0" />
                <div>
                  <div className="text-xs font-bold text-gray-900 dark:text-white">Cash on Delivery (COD)</div>
                  <div className="text-[11px] text-gray-500">Pay cash upon parcel receipt</div>
                </div>
              </label>

              <label
                onClick={() => setPaymentMethod('mock_card')}
                className={`p-4 rounded-2xl border cursor-pointer flex items-center gap-3 transition-all ${
                  paymentMethod === 'mock_card'
                    ? 'border-brand-600 bg-brand-50/50 dark:bg-brand-950/40 ring-2 ring-brand-600/20'
                    : 'border-gray-200 dark:border-gray-800'
                }`}
              >
                <input
                  type="radio"
                  name="payment"
                  checked={paymentMethod === 'mock_card'}
                  onChange={() => setPaymentMethod('mock_card')}
                  className="text-brand-600"
                />
                <CreditCard className="w-5 h-5 text-indigo-600 shrink-0" />
                <div>
                  <div className="text-xs font-bold text-gray-900 dark:text-white">Card / Digital Payment</div>
                  <div className="text-[11px] text-gray-500">Instant test authorization</div>
                </div>
              </label>
            </div>
          </div>
        </div>

        {/* Order Summary & Place Button */}
        <div className="space-y-4">
          <div className="p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4 shadow-sm">
            <h3 className="font-bold text-sm text-gray-900 dark:text-white">Order Summary</h3>

            {/* Line items preview */}
            <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
              {items.map((item) => (
                <div key={item.id} className="flex items-center gap-3 text-xs">
                  <img
                    src={item.image}
                    alt={item.name}
                    className="w-10 h-10 rounded-lg object-cover bg-gray-100 dark:bg-gray-800 shrink-0"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-gray-900 dark:text-white truncate">{item.name}</p>
                    <p className="text-[11px] text-gray-500">Qty: {item.quantity}</p>
                  </div>
                  <span className="font-bold text-gray-900 dark:text-white">
                    ${(item.total_price || (item.unit_price || item.price) * item.quantity).toFixed(2)}
                  </span>
                </div>
              ))}
            </div>

            {/* Promotional Voucher Input */}
            <div className="pt-3 border-t border-gray-100 dark:border-gray-800">
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] font-bold text-gray-600 dark:text-gray-400">
                  Coupon Code
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
                  className="flex-1 px-3 py-1.5 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white uppercase font-mono focus:outline-none focus:border-brand-500"
                />
                <button
                  type="button"
                  onClick={(e) => handleApplyCoupon(e)}
                  disabled={isValidatingCoupon}
                  className="px-3 py-1.5 bg-gray-900 dark:bg-white text-white dark:text-gray-900 rounded-xl text-xs font-bold hover:bg-brand-600 dark:hover:bg-brand-600 dark:hover:text-white transition-colors disabled:opacity-60 cursor-pointer"
                >
                  {isValidatingCoupon ? 'Checking...' : 'Apply'}
                </button>
              </div>

              {/* Available Coupons Drawer */}
              {availableCoupons.length > 0 && showCouponsList && (
                <div className="space-y-1.5 pt-2">
                  <div className="text-[10px] font-bold text-gray-400 flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-amber-500" />
                    <span>Eligible Offers</span>
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                    {availableCoupons.map((c) => {
                      const isApplied = appliedCoupon?.code === c.code;
                      const qualifies = subtotal >= c.min_order_value;
                      const diff = (c.min_order_value - subtotal).toFixed(2);

                      return (
                        <div
                          key={c.id}
                          className={cn(
                            "p-2 rounded-xl border transition-all text-xs flex items-center justify-between gap-1.5",
                            isApplied 
                              ? "border-emerald-500 bg-emerald-50/50 dark:bg-emerald-950/20" 
                              : "border-gray-200 dark:border-gray-800 bg-gray-50/80 dark:bg-gray-800/40"
                          )}
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1">
                              <span className="font-mono font-black text-gray-900 dark:text-white text-[10px] px-1 py-0.2 rounded bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700">
                                {c.code}
                              </span>
                              <span className="font-bold text-[9px] text-brand-600 dark:text-brand-400">
                                {c.badge}
                              </span>
                            </div>
                            <p className="text-[9px] text-gray-500 mt-0.5 truncate">
                              {c.description}
                            </p>
                            {!qualifies && (
                              <p className="text-[8.5px] text-amber-600 dark:text-amber-400 font-medium">
                                Add ${diff} more to qualify
                              </p>
                            )}
                          </div>

                          <div>
                            {isApplied ? (
                              <span className="text-[9px] font-bold text-emerald-600 flex items-center gap-0.5">
                                <Check className="w-3 h-3" /> Applied
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handleApplyCoupon(null, c.code)}
                                disabled={!qualifies || isValidatingCoupon}
                                className={cn(
                                  "px-2 py-0.5 rounded-lg text-[9px] font-bold transition-colors cursor-pointer",
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
            </div>

            {/* Calculations Breakdown */}
            <div className="space-y-2 text-xs text-gray-500 pt-2 border-t border-gray-100 dark:border-gray-800">
              <div className="flex justify-between">
                <span>Subtotal ({totalItems} items)</span>
                <span className="font-semibold text-gray-900 dark:text-white">${subtotal.toFixed(2)}</span>
              </div>

              <div className="flex justify-between">
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
                    <button type="button" onClick={handleRemoveCoupon} className="text-gray-400 hover:text-rose-500 ml-1">×</button>
                  </span>
                  <span>-${couponDiscount.toFixed(2)}</span>
                </div>
              )}

              <div className="pt-3 border-t border-gray-200 dark:border-gray-800 flex justify-between text-base font-black text-gray-900 dark:text-white">
                <span>Total Due</span>
                <span>${finalTotal.toFixed(2)}</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || items.length === 0}
              className="w-full py-3.5 rounded-2xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-md shadow-brand-600/30 transition-all disabled:opacity-70"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Authorizing & Placing Order...
                </>
              ) : (
                <>
                  Place Order Now <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>

            <div className="flex items-center gap-2 text-[11px] text-gray-500 justify-center pt-1">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              <span>Safe 256-Bit Encrypted Order</span>
            </div>
          </div>
        </div>
      </form>
    </div>
  );
}

import { Link } from 'react-router-dom';
import { Truck, RotateCcw, ShieldCheck, Headphones, Heart, ArrowRight } from 'lucide-react';

export function StorefrontFooter() {
  return (
    <footer className="bg-gray-900 text-gray-300 border-t border-gray-800 transition-colors">
      {/* Value Propositions / Trust Strip */}
      <div className="border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center sm:text-left">
            
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-3">
              <div className="p-3 rounded-2xl bg-brand-500/10 text-brand-400 border border-brand-500/20">
                <Truck className="w-6 h-6" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-white">Free Expedited Shipping</h4>
                <p className="text-xs text-gray-400 mt-0.5">On all qualified orders over $49</p>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-3">
              <div className="p-3 rounded-2xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <RotateCcw className="w-6 h-6" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-white">30-Day Easy Returns</h4>
                <p className="text-xs text-gray-400 mt-0.5">Hassle-free replacement guarantee</p>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-3">
              <div className="p-3 rounded-2xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-white">100% Secure Checkout</h4>
                <p className="text-xs text-gray-400 mt-0.5">256-bit encrypted transactions</p>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-3">
              <div className="p-3 rounded-2xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                <Headphones className="w-6 h-6" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-white">24/7 Dedicated Support</h4>
                <p className="text-xs text-gray-400 mt-0.5">Instant help whenever you need it</p>
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* Main Footer Links */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-8">
          
          {/* Brand Info & Newsletter */}
          <div className="lg:col-span-2 space-y-4">
            <Link to="/" className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-brand-600 to-indigo-500 flex items-center justify-center text-white font-black text-lg">
                A
              </div>
              <span className="text-xl font-extrabold text-white tracking-tight">ApexStore</span>
            </Link>
            <p className="text-sm text-gray-400 max-w-sm leading-relaxed">
              Your premier destination for high-performance technology, modern lifestyle products, and authentic customer care.
            </p>

            <div className="pt-2">
              <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider mb-2">
                Subscribe for exclusive discounts
              </p>
              <form onSubmit={(e) => e.preventDefault()} className="flex max-w-md gap-2">
                <input
                  type="email"
                  placeholder="Enter your email"
                  className="bg-gray-800 border border-gray-700 rounded-xl px-4 py-2.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-brand-500 w-full"
                />
                <button
                  type="submit"
                  className="bg-brand-600 hover:bg-brand-700 text-white px-4 py-2.5 rounded-xl text-xs font-semibold flex items-center gap-1 shrink-0 transition-colors"
                >
                  Join <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </form>
            </div>
          </div>

          {/* Column 1: Shop */}
          <div className="space-y-3">
            <h5 className="text-sm font-bold text-white uppercase tracking-wider">Shop Catalog</h5>
            <ul className="space-y-2 text-xs text-gray-400">
              <li><Link to="/products?category=Electronics" className="hover:text-white transition-colors">Electronics & Audio</Link></li>
              <li><Link to="/products?category=Fashion" className="hover:text-white transition-colors">Apparel & Footwear</Link></li>
              <li><Link to="/products?category=Home" className="hover:text-white transition-colors">Home & Living</Link></li>
              <li><Link to="/products?category=Beauty" className="hover:text-white transition-colors">Beauty & Personal Care</Link></li>
              <li><Link to="/products?badge=deal" className="hover:text-rose-400 font-semibold transition-colors">Featured Flash Deals</Link></li>
            </ul>
          </div>

          {/* Column 2: Customer Care */}
          <div className="space-y-3">
            <h5 className="text-sm font-bold text-white uppercase tracking-wider">Customer Care</h5>
            <ul className="space-y-2 text-xs text-gray-400">
              <li><Link to="/orders" className="hover:text-white transition-colors">Track Your Order</Link></li>
              <li><Link to="/cart" className="hover:text-white transition-colors">Shipping Rates & Policies</Link></li>
              <li><Link to="/account" className="hover:text-white transition-colors">Returns & Refunds</Link></li>
              <li><Link to="/account" className="hover:text-white transition-colors">Account Management</Link></li>
              <li><a href="#help" className="hover:text-white transition-colors">Help Center / FAQ</a></li>
            </ul>
          </div>

          {/* Column 3: Trust & Company */}
          <div className="space-y-3">
            <h5 className="text-sm font-bold text-white uppercase tracking-wider">Company & Legal</h5>
            <ul className="space-y-2 text-xs text-gray-400">
              <li><a href="#about" className="hover:text-white transition-colors">About ApexStore</a></li>
              <li><a href="#privacy" className="hover:text-white transition-colors">Privacy Policy</a></li>
              <li><a href="#terms" className="hover:text-white transition-colors">Terms of Service</a></li>
              <li><a href="#security" className="hover:text-white transition-colors">Security Architecture</a></li>
              <li><a href="#contact" className="hover:text-white transition-colors">Contact Us</a></li>
            </ul>
          </div>

        </div>
      </div>

      {/* Bottom Legal & Payment Bar */}
      <div className="border-t border-gray-800 bg-gray-950/60 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-gray-500">
          <p>© {new Date().getFullYear()} ApexStore Inc. All rights reserved. Original e-commerce design.</p>
          <div className="flex items-center gap-3 font-mono text-[11px] text-gray-400">
            <span className="px-2 py-1 rounded bg-gray-800 border border-gray-700">VISA</span>
            <span className="px-2 py-1 rounded bg-gray-800 border border-gray-700">MASTERCARD</span>
            <span className="px-2 py-1 rounded bg-gray-800 border border-gray-700">AMEX</span>
            <span className="px-2 py-1 rounded bg-gray-800 border border-gray-700">PAYPAL</span>
            <span className="px-2 py-1 rounded bg-gray-800 border border-gray-700">COD</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

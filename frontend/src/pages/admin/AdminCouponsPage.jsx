import { useState, useEffect } from 'react';
import { 
  TicketPercent, Tag, Plus, Search, Filter, Check, Copy, 
  Calendar, TrendingUp, Sparkles, Clock, AlertCircle, Trash2, 
  Edit, Eye, RefreshCw, X, Percent, DollarSign, CheckCircle2,
  Users, ShoppingCart
} from 'lucide-react';
import { adminCouponService } from '../../services/api';
import { toast } from 'react-hot-toast';
import { cn } from '../../utils/helpers';

export default function AdminCouponsPage() {
  const [coupons, setCoupons] = useState([]);
  const [stats, setStats] = useState({
    total_coupons: 0,
    active_coupons: 0,
    total_redemptions: 0,
    total_savings_distributed: 0,
  });
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');

  // Modal states
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingCoupon, setEditingCoupon] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [copiedCode, setCopiedCode] = useState(null);

  // Usages inspection modal state
  const [viewingUsagesCoupon, setViewingUsagesCoupon] = useState(null);
  const [usagesList, setUsagesList] = useState([]);
  const [loadingUsages, setLoadingUsages] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    code: '',
    description: '',
    discount_type: 'percentage',
    discount_value: '',
    min_order_value: '',
    max_discount_amount: '',
    usage_limit: '100',
    expiry_date: '',
    is_active: true,
  });

  const fetchCoupons = async () => {
    try {
      setLoading(true);
      const params = {};
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (statusFilter !== 'all') params.status = statusFilter;
      if (typeFilter !== 'all') params.discount_type = typeFilter;

      const res = await adminCouponService.getCoupons(params);
      if (res.success) {
        setCoupons(res.coupons || []);
        if (res.stats) setStats(res.stats);
      }
    } catch (err) {
      console.error(err);
      toast.error('Failed to load coupons');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchCoupons();
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery, statusFilter, typeFilter]);

  const handleOpenCreateModal = () => {
    setEditingCoupon(null);
    setFormData({
      code: '',
      description: '',
      discount_type: 'percentage',
      discount_value: '',
      min_order_value: '',
      max_discount_amount: '',
      usage_limit: '100',
      expiry_date: '',
      is_active: true,
    });
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (coupon) => {
    setEditingCoupon(coupon);
    setFormData({
      code: coupon.code,
      description: coupon.description || '',
      discount_type: coupon.discount_type,
      discount_value: coupon.discount_value.toString(),
      min_order_value: coupon.min_order_value ? coupon.min_order_value.toString() : '',
      max_discount_amount: coupon.max_discount_amount ? coupon.max_discount_amount.toString() : '',
      usage_limit: coupon.usage_limit ? coupon.usage_limit.toString() : '100',
      expiry_date: coupon.expiry_date ? coupon.expiry_date.substring(0, 10) : '',
      is_active: coupon.is_active,
    });
    setIsModalOpen(true);
  };

  const handleGenerateRandomCode = () => {
    const prefixes = ['PROMO', 'SALE', 'SAVE', 'VIP', 'FLASH', 'APEX'];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const val = formData.discount_value ? Math.round(Number(formData.discount_value)) : 15;
    const rand = Math.floor(10 + Math.random() * 90);
    setFormData(prev => ({ ...prev, code: `${prefix}${val || 10}_${rand}` }));
  };

  const handleSaveCoupon = async (e) => {
    e.preventDefault();
    const code = formData.code.trim().toUpperCase();
    if (!code) {
      toast.error('Coupon code is required');
      return;
    }

    const discVal = parseFloat(formData.discount_value);
    if (isNaN(discVal) || discVal <= 0) {
      toast.error('Discount value must be greater than 0');
      return;
    }

    if (formData.discount_type === 'percentage' && discVal > 100) {
      toast.error('Percentage discount cannot exceed 100%');
      return;
    }

    const payload = {
      code,
      description: formData.description.trim(),
      discount_type: formData.discount_type,
      discount_value: discVal,
      min_order_value: formData.min_order_value ? parseFloat(formData.min_order_value) : 0,
      max_discount_amount: formData.max_discount_amount ? parseFloat(formData.max_discount_amount) : null,
      usage_limit: formData.usage_limit ? parseInt(formData.usage_limit, 10) : 100,
      expiry_date: formData.expiry_date ? `${formData.expiry_date}T23:59:59` : null,
      is_active: formData.is_active,
    };

    try {
      setIsSubmitting(true);
      if (editingCoupon) {
        const res = await adminCouponService.updateCoupon(editingCoupon.id, payload);
        toast.success(res.message || 'Coupon updated successfully');
      } else {
        const res = await adminCouponService.createCoupon(payload);
        toast.success(res.message || 'Coupon created successfully');
      }
      setIsModalOpen(false);
      fetchCoupons();
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to save coupon';
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleStatus = async (coupon) => {
    try {
      const res = await adminCouponService.toggleCouponStatus(coupon.id);
      toast.success(res.message);
      setCoupons(prev => prev.map(c => c.id === coupon.id ? { 
        ...c, 
        is_active: res.is_active,
        status_label: res.is_active ? 'ACTIVE' : 'INACTIVE'
      } : c));
      // update stats
      setStats(prev => ({
        ...prev,
        active_coupons: res.is_active ? prev.active_coupons + 1 : Math.max(0, prev.active_coupons - 1)
      }));
    } catch (err) {
      toast.error('Failed to change status');
    }
  };

  const handleDeleteCoupon = async (coupon) => {
    if (!window.confirm(`Are you sure you want to delete coupon "${coupon.code}"?`)) return;

    try {
      const res = await adminCouponService.deleteCoupon(coupon.id);
      toast.success(res.message);
      fetchCoupons();
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to delete coupon');
    }
  };

  const handleCopyCode = (code) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(code);
    toast.success(`Copied "${code}" to clipboard!`);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const handleViewUsages = async (coupon) => {
    setViewingUsagesCoupon(coupon);
    setLoadingUsages(true);
    try {
      const usages = await adminCouponService.getCouponUsages(coupon.id);
      setUsagesList(usages);
    } catch (err) {
      toast.error('Failed to fetch coupon usages');
    } finally {
      setLoadingUsages(false);
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <TicketPercent className="w-7 h-7 text-brand-600 dark:text-brand-400" />
            Coupons & Promotions
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Create promotional discount codes, enforce spending minimums, set redemption caps, and track campaign ROI.
          </p>
        </div>

        <button
          onClick={handleOpenCreateModal}
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-brand-600 hover:bg-brand-700 text-white text-xs font-bold rounded-2xl shadow-md shadow-brand-600/20 transition-all cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          Create New Coupon
        </button>
      </div>

      {/* KPI Stats Overview */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Vouchers</span>
            <div className="w-8 h-8 rounded-xl bg-blue-50 dark:bg-blue-950/40 text-blue-600 flex items-center justify-center">
              <Tag className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.total_coupons}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Catalog promo codes</span>
        </div>

        <div className="p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Active Campaigns</span>
            <div className="w-8 h-8 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 flex items-center justify-center">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-emerald-600 mt-2">
            {stats.active_coupons}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Currently redeemable</span>
        </div>

        <div className="p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Redemptions</span>
            <div className="w-8 h-8 rounded-xl bg-purple-50 dark:bg-purple-950/40 text-purple-600 flex items-center justify-center">
              <Users className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.total_redemptions}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Orders discounted</span>
        </div>

        <div className="p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Savings Given</span>
            <div className="w-8 h-8 rounded-xl bg-amber-50 dark:bg-amber-950/40 text-amber-600 flex items-center justify-center">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            ${Number(stats.total_savings_distributed).toFixed(2)}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Customer discount value</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search code or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <div className="flex bg-gray-100 dark:bg-gray-800 p-1 rounded-2xl text-xs font-medium text-gray-600 dark:text-gray-300">
            {['all', 'active', 'inactive', 'expired'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={cn(
                  "px-3 py-1.5 rounded-xl capitalize transition-all",
                  statusFilter === st 
                    ? "bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-bold shadow-xs" 
                    : "hover:text-gray-900 dark:hover:text-white"
                )}
              >
                {st}
              </button>
            ))}
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-200 focus:outline-none"
          >
            <option value="all">All Types</option>
            <option value="percentage">Percentage (%)</option>
            <option value="fixed">Fixed ($)</option>
          </select>

          <button
            onClick={fetchCoupons}
            className="p-2 rounded-xl text-gray-500 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            title="Refresh coupons"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Coupons List / Table */}
      <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800 overflow-hidden shadow-xs">
        {loading && coupons.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-xs">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-brand-600" />
            Loading promotional coupons...
          </div>
        ) : coupons.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <TicketPercent className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-700" />
            <h3 className="text-sm font-bold text-gray-900 dark:text-white">No promotional coupons found</h3>
            <p className="text-xs text-gray-500 max-w-sm mx-auto">
              Create your first promotional code to attract new buyers and boost storefront checkout conversion.
            </p>
            <button
              onClick={handleOpenCreateModal}
              className="px-4 py-2 bg-brand-600 text-white rounded-xl text-xs font-bold hover:bg-brand-700 inline-flex items-center gap-1.5"
            >
              <Plus className="w-4 h-4" /> Create Coupon
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 dark:bg-gray-950/50 text-gray-500 border-b border-gray-200 dark:border-gray-800 uppercase tracking-wider text-[10px] font-bold">
                <tr>
                  <th className="py-3.5 px-4">Coupon Code</th>
                  <th className="py-3.5 px-4">Discount Value</th>
                  <th className="py-3.5 px-4">Rules & Limits</th>
                  <th className="py-3.5 px-4">Redemption Quota</th>
                  <th className="py-3.5 px-4">Validity</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800/60 font-normal">
                {coupons.map((coupon) => {
                  const usagePct = coupon.usage_limit 
                    ? Math.min(100, Math.round((coupon.times_used / coupon.usage_limit) * 100))
                    : 0;

                  return (
                    <tr key={coupon.id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/30 transition-colors">
                      {/* Code */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-black text-sm text-gray-900 dark:text-white px-2.5 py-1 rounded-lg bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                            {coupon.code}
                          </span>
                          <button
                            onClick={() => handleCopyCode(coupon.code)}
                            className="p-1 text-gray-400 hover:text-brand-600 transition-colors"
                            title="Copy code"
                          >
                            {copiedCode === coupon.code ? (
                              <Check className="w-3.5 h-3.5 text-emerald-500" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                        <p className="text-[11px] text-gray-500 mt-1 max-w-xs truncate">
                          {coupon.description}
                        </p>
                      </td>

                      {/* Discount Value */}
                      <td className="py-3.5 px-4">
                        <span className={cn(
                          "inline-flex items-center gap-1 font-black px-2.5 py-1 rounded-full text-xs",
                          coupon.discount_type === 'percentage' 
                            ? "bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300"
                            : "bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300"
                        )}>
                          {coupon.discount_type === 'percentage' ? (
                            <Percent className="w-3 h-3" />
                          ) : (
                            <DollarSign className="w-3 h-3" />
                          )}
                          {coupon.badge}
                        </span>
                      </td>

                      {/* Rules & Limits */}
                      <td className="py-3.5 px-4 text-[11px] text-gray-600 dark:text-gray-400 space-y-0.5">
                        <div>Min Spend: <span className="font-semibold text-gray-900 dark:text-white">${coupon.min_order_value.toFixed(2)}</span></div>
                        {coupon.max_discount_amount && (
                          <div>Max Savings: <span className="font-semibold text-gray-900 dark:text-white">${coupon.max_discount_amount.toFixed(2)}</span></div>
                        )}
                      </td>

                      {/* Usage */}
                      <td className="py-3.5 px-4 min-w-[140px]">
                        <div className="flex items-center justify-between text-[11px] mb-1">
                          <span className="font-bold text-gray-900 dark:text-white">{coupon.times_used}</span>
                          <span className="text-gray-400">of {coupon.usage_limit || '∞'} uses</span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-gray-100 dark:bg-gray-800 overflow-hidden">
                          <div 
                            className={cn(
                              "h-full rounded-full transition-all",
                              usagePct >= 90 ? "bg-rose-500" : usagePct >= 50 ? "bg-amber-500" : "bg-brand-600"
                            )}
                            style={{ width: `${usagePct}%` }}
                          />
                        </div>
                        <div className="text-[10px] text-gray-400 mt-1">
                          ${coupon.total_savings_distributed.toFixed(2)} savings saved
                        </div>
                      </td>

                      {/* Validity */}
                      <td className="py-3.5 px-4 text-[11px] text-gray-500">
                        {coupon.expiry_date ? (
                          <div className="flex items-center gap-1">
                            <Clock className="w-3 h-3 text-gray-400" />
                            <span>{new Date(coupon.expiry_date).toLocaleDateString()}</span>
                          </div>
                        ) : (
                          <span className="text-gray-400 italic">No expiration</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        <button
                          onClick={() => handleToggleStatus(coupon)}
                          className={cn(
                            "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-bold text-[10px] transition-all cursor-pointer",
                            coupon.status_label === 'ACTIVE' 
                              ? "bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-200"
                              : coupon.status_label === 'EXPIRED'
                              ? "bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300"
                              : coupon.status_label === 'DEPLETED'
                              ? "bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300"
                              : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200"
                          )}
                          title="Click to toggle active status"
                        >
                          <span className={cn(
                            "w-1.5 h-1.5 rounded-full",
                            coupon.status_label === 'ACTIVE' ? "bg-emerald-500 animate-pulse" : "bg-gray-400"
                          )} />
                          {coupon.status_label}
                        </button>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            onClick={() => handleViewUsages(coupon)}
                            className="p-1.5 text-gray-400 hover:text-brand-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                            title="View usage orders"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleOpenEditModal(coupon)}
                            className="p-1.5 text-gray-400 hover:text-blue-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                            title="Edit coupon"
                          >
                            <Edit className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteCoupon(coupon)}
                            className="p-1.5 text-gray-400 hover:text-rose-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                            title="Delete coupon"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create / Edit Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl w-full max-w-lg shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <TicketPercent className="w-5 h-5 text-brand-600" />
                <h3 className="font-black text-sm text-gray-900 dark:text-white">
                  {editingCoupon ? `Edit Coupon "${editingCoupon.code}"` : 'Create New Promotional Coupon'}
                </h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveCoupon} className="p-6 space-y-4 overflow-y-auto flex-1">
              {/* Code input with generator */}
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Coupon Code *
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    required
                    placeholder="e.g. FLASH25"
                    value={formData.code}
                    onChange={(e) => setFormData({ ...formData, code: e.target.value.toUpperCase() })}
                    className="flex-1 px-3 py-2 text-xs font-mono font-bold uppercase rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                  <button
                    type="button"
                    onClick={handleGenerateRandomCode}
                    className="px-3 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-xl text-xs font-bold hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors flex items-center gap-1"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-amber-500" />
                    Auto-Generate
                  </button>
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Promotional Headline / Description
                </label>
                <input
                  type="text"
                  placeholder="e.g. Special Holiday Sale: 20% off all orders over $50"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              {/* Discount Type & Value */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Discount Type *
                  </label>
                  <select
                    value={formData.discount_type}
                    onChange={(e) => setFormData({ ...formData, discount_type: e.target.value })}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  >
                    <option value="percentage">Percentage (%)</option>
                    <option value="fixed">Fixed Amount ($)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Discount Value * {formData.discount_type === 'percentage' ? '(%)' : '($)'}
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    min="0.01"
                    max={formData.discount_type === 'percentage' ? '100' : undefined}
                    required
                    placeholder={formData.discount_type === 'percentage' ? '20' : '10.00'}
                    value={formData.discount_value}
                    onChange={(e) => setFormData({ ...formData, discount_value: e.target.value })}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
              </div>

              {/* Min Spend & Max Discount */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Minimum Order Value ($)
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    min="0"
                    placeholder="0.00 (No minimum)"
                    value={formData.min_order_value}
                    onChange={(e) => setFormData({ ...formData, min_order_value: e.target.value })}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Max Discount Cap ($)
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    min="0.01"
                    placeholder="e.g. 50.00 (Optional cap)"
                    value={formData.max_discount_amount}
                    onChange={(e) => setFormData({ ...formData, max_discount_amount: e.target.value })}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
              </div>

              {/* Usage Limit & Expiry Date */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Usage Limit (Max Uses)
                  </label>
                  <input
                    type="number"
                    min="1"
                    placeholder="100"
                    value={formData.usage_limit}
                    onChange={(e) => setFormData({ ...formData, usage_limit: e.target.value })}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Expiry Date
                  </label>
                  <input
                    type="date"
                    value={formData.expiry_date}
                    onChange={(e) => setFormData({ ...formData, expiry_date: e.target.value })}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
              </div>

              {/* Active Switch */}
              <label className="flex items-center gap-2 pt-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.is_active}
                  onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                  className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                />
                <span className="text-xs font-bold text-gray-800 dark:text-gray-200">
                  Enable and activate coupon immediately
                </span>
              </label>

              {/* Modal Actions */}
              <div className="pt-4 border-t border-gray-200 dark:border-gray-800 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 rounded-xl text-xs font-bold bg-brand-600 hover:bg-brand-700 text-white shadow-md shadow-brand-600/20 disabled:opacity-50"
                >
                  {isSubmitting ? 'Saving...' : (editingCoupon ? 'Update Coupon' : 'Create Coupon')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Usages Inspection Modal */}
      {viewingUsagesCoupon && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl w-full max-w-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
              <div>
                <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                  <TicketPercent className="w-4 h-4 text-brand-600" />
                  Redemption History: {viewingUsagesCoupon.code}
                </h3>
                <p className="text-[11px] text-gray-500">
                  {viewingUsagesCoupon.times_used} total uses • ${viewingUsagesCoupon.total_savings_distributed.toFixed(2)} total savings given
                </p>
              </div>
              <button
                onClick={() => setViewingUsagesCoupon(null)}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1">
              {loadingUsages ? (
                <div className="p-8 text-center text-xs text-gray-500">
                  <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-brand-600" />
                  Fetching redemption records...
                </div>
              ) : usagesList.length === 0 ? (
                <div className="p-8 text-center text-xs text-gray-500">
                  No orders have redeemed this coupon code yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {usagesList.map((usage) => (
                    <div
                      key={usage.id}
                      className="p-3.5 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-100 dark:border-gray-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="font-bold text-gray-900 dark:text-white">
                          {usage.user_name}
                        </div>
                        <div className="text-[11px] text-gray-500">{usage.user_email}</div>
                        <div className="text-[10px] text-gray-400 mt-1">
                          Order: <span className="font-mono text-gray-700 dark:text-gray-300">{usage.order_number}</span> ({usage.order_status})
                        </div>
                      </div>

                      <div className="text-right">
                        <div className="font-black text-emerald-600 dark:text-emerald-400 text-sm">
                          -${usage.discount_amount.toFixed(2)}
                        </div>
                        <div className="text-[10px] text-gray-400 mt-0.5">
                          {new Date(usage.used_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

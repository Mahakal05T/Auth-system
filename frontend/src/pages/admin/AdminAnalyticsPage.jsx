import { useState, useEffect, useMemo } from 'react';
import { 
  BarChart3, TrendingUp, DollarSign, ShoppingBag, 
  Users, Star, RefreshCw, Calendar, ArrowUpRight, 
  Package, CreditCard, Layers, Award, RotateCcw, 
  Percent, Truck, CheckCircle2, Clock
} from 'lucide-react';
import { adminAnalyticsService } from '../../services/api';
import { toast } from 'react-hot-toast';
import { cn } from '../../utils/helpers';
import { Link } from 'react-router-dom';

export default function AdminAnalyticsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeframe, setTimeframe] = useState('30d');
  const [chartMetric, setChartMetric] = useState('revenue'); // 'revenue' or 'orders'
  const [hoveredPoint, setHoveredPoint] = useState(null);

  const fetchAnalytics = async (tf = timeframe) => {
    try {
      setLoading(true);
      const res = await adminAnalyticsService.getOverview(tf);
      if (res.success) {
        setData(res);
      }
    } catch (err) {
      console.error('Failed to load analytics:', err);
      toast.error('Failed to load business analytics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics(timeframe);
  }, [timeframe]);

  const kpis = data?.kpis || {};
  const chartSeries = data?.chart_series || [];
  const categories = data?.category_distribution || [];
  const topProducts = data?.top_products || [];
  const paymentMethods = data?.payment_methods || [];
  const recentTransactions = data?.recent_transactions || [];

  // Calculate chart max for scaling
  const maxChartValue = useMemo(() => {
    if (!chartSeries.length) return 100;
    const values = chartSeries.map(p => chartMetric === 'revenue' ? p.revenue : p.orders);
    const max = Math.max(...values, 0);
    return max === 0 ? 100 : max * 1.15; // 15% headroom
  }, [chartSeries, chartMetric]);

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Page Header with Timeframe Pill Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <BarChart3 className="w-7 h-7 text-brand-600 dark:text-brand-400" />
            Executive Sales & Performance Analytics
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Real-time commercial business intelligence, revenue growth trajectory, customer retention, and inventory velocity.
          </p>
        </div>

        {/* Timeframe Controls */}
        <div className="flex items-center gap-2 self-start md:self-auto flex-wrap">
          <div className="flex items-center bg-gray-100 dark:bg-gray-800 p-1 rounded-2xl text-xs font-semibold text-gray-600 dark:text-gray-300">
            {[
              { id: '7d', label: '7 Days' },
              { id: '30d', label: '30 Days' },
              { id: '90d', label: '90 Days' },
              { id: '1y', label: '1 Year' },
              { id: 'all', label: 'All Time' },
            ].map((tf) => (
              <button
                key={tf.id}
                onClick={() => setTimeframe(tf.id)}
                className={cn(
                  "px-3 py-1.5 rounded-xl transition-all cursor-pointer",
                  timeframe === tf.id
                    ? "bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-bold shadow-xs"
                    : "hover:text-gray-900 dark:hover:text-white"
                )}
              >
                {tf.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => fetchAnalytics(timeframe)}
            disabled={loading}
            className="p-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 rounded-2xl shadow-xs transition-colors cursor-pointer"
            title="Refresh Data"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Top Level Financial KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Gross Revenue */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500">Gross Sales</span>
            <div className="w-9 h-9 rounded-2xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 flex items-center justify-center">
              <DollarSign className="w-5 h-5" />
            </div>
          </div>
          <div className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white mt-3 tracking-tight">
            ${(kpis.gross_revenue || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
          </div>
          <div className="flex items-center gap-1.5 mt-1 text-[11px] text-gray-400">
            <span>Discounts: ${kpis.total_discounts?.toFixed(2) || '0.00'}</span>
          </div>
        </div>

        {/* Net Revenue */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500">Net Revenue</span>
            <div className="w-9 h-9 rounded-2xl bg-brand-50 dark:bg-brand-950/40 text-brand-600 flex items-center justify-center">
              <TrendingUp className="w-5 h-5" />
            </div>
          </div>
          <div className="text-2xl sm:text-3xl font-black text-brand-600 dark:text-brand-400 mt-3 tracking-tight">
            ${(kpis.net_revenue || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
          </div>
          <div className="flex items-center gap-1.5 mt-1 text-[11px] text-gray-400">
            <span>Refunds: ${kpis.total_refunds?.toFixed(2) || '0.00'}</span>
          </div>
        </div>

        {/* Average Order Value (AOV) */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500">Average Order Value</span>
            <div className="w-9 h-9 rounded-2xl bg-purple-50 dark:bg-purple-950/40 text-purple-600 flex items-center justify-center">
              <ShoppingBag className="w-5 h-5" />
            </div>
          </div>
          <div className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white mt-3 tracking-tight">
            ${(kpis.average_order_value || 0).toFixed(2)}
          </div>
          <div className="flex items-center gap-1.5 mt-1 text-[11px] text-gray-400">
            <span>Across {kpis.total_orders || 0} total orders</span>
          </div>
        </div>

        {/* Total Units Sold */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500">Units Dispatched</span>
            <div className="w-9 h-9 rounded-2xl bg-blue-50 dark:bg-blue-950/40 text-blue-600 flex items-center justify-center">
              <Package className="w-5 h-5" />
            </div>
          </div>
          <div className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white mt-3 tracking-tight">
            {kpis.total_units_sold || 0}
          </div>
          <div className="flex items-center gap-1.5 mt-1 text-[11px] text-gray-400">
            <span>{kpis.active_buyers || 0} active buyer accounts</span>
          </div>
        </div>
      </div>

      {/* Secondary Performance Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-xs">
        <div className="flex items-center gap-3 px-2">
          <div className="w-8 h-8 rounded-xl bg-amber-50 dark:bg-amber-950/40 text-amber-600 flex items-center justify-center shrink-0">
            <Star className="w-4 h-4 fill-amber-500 text-amber-500" />
          </div>
          <div>
            <div className="text-[11px] text-gray-400 font-medium">Customer Rating</div>
            <div className="font-bold text-gray-900 dark:text-white">
              {kpis.average_review_rating || 5.0} / 5.0 <span className="text-gray-400 font-normal">({kpis.total_reviews || 0} reviews)</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-2 border-l border-gray-100 dark:border-gray-800">
          <div className="w-8 h-8 rounded-xl bg-teal-50 dark:bg-teal-950/40 text-teal-600 flex items-center justify-center shrink-0">
            <Users className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] text-gray-400 font-medium">Repeat Buyer Rate</div>
            <div className="font-bold text-gray-900 dark:text-white">
              {kpis.repeat_customer_rate || 0}% <span className="text-gray-400 font-normal">loyalty</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-2 border-l border-gray-100 dark:border-gray-800">
          <div className="w-8 h-8 rounded-xl bg-indigo-50 dark:bg-indigo-950/40 text-indigo-600 flex items-center justify-center shrink-0">
            <CheckCircle2 className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] text-gray-400 font-medium">Fulfilled Volume</div>
            <div className="font-bold text-gray-900 dark:text-white">
              {kpis.completed_orders || 0} <span className="text-gray-400 font-normal">completed orders</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 px-2 border-l border-gray-100 dark:border-gray-800">
          <div className="w-8 h-8 rounded-xl bg-rose-50 dark:bg-rose-950/40 text-rose-600 flex items-center justify-center shrink-0">
            <RotateCcw className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] text-gray-400 font-medium">Return Rate</div>
            <div className="font-bold text-gray-900 dark:text-white">
              {kpis.total_orders ? ((kpis.returned_orders / kpis.total_orders) * 100).toFixed(1) : 0}% <span className="text-gray-400 font-normal">({kpis.returned_orders || 0} returns)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Revenue Trajectory Visual Chart */}
      <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-brand-600" />
              Revenue & Order Volume Trajectory
            </h3>
            <p className="text-xs text-gray-400">
              Daily trend breakdown over the selected timeframe ({timeframe.toUpperCase()}).
            </p>
          </div>

          {/* Metric Toggle */}
          <div className="flex items-center bg-gray-100 dark:bg-gray-800 p-1 rounded-xl text-xs font-semibold self-start sm:self-auto">
            <button
              onClick={() => setChartMetric('revenue')}
              className={cn(
                "px-3 py-1 rounded-lg transition-all cursor-pointer",
                chartMetric === 'revenue'
                  ? "bg-white dark:bg-gray-900 text-brand-600 dark:text-brand-400 font-bold shadow-xs"
                  : "text-gray-500 hover:text-gray-900 dark:hover:text-white"
              )}
            >
              Revenue ($)
            </button>
            <button
              onClick={() => setChartMetric('orders')}
              className={cn(
                "px-3 py-1 rounded-lg transition-all cursor-pointer",
                chartMetric === 'orders'
                  ? "bg-white dark:bg-gray-900 text-brand-600 dark:text-brand-400 font-bold shadow-xs"
                  : "text-gray-500 hover:text-gray-900 dark:hover:text-white"
              )}
            >
              Order Count
            </button>
          </div>
        </div>

        {/* Dynamic Chart Container */}
        <div className="relative pt-6 pb-2">
          {chartSeries.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-xs text-gray-400">
              No historical trend data for this timeframe.
            </div>
          ) : (
            <div className="h-60 flex items-end gap-1 sm:gap-2 px-2 border-b border-gray-200 dark:border-gray-800">
              {chartSeries.map((pt, idx) => {
                const val = chartMetric === 'revenue' ? pt.revenue : pt.orders;
                const heightPercent = maxChartValue > 0 ? Math.max(4, Math.round((val / maxChartValue) * 100)) : 4;
                const isHovered = hoveredPoint?.date === pt.date;

                return (
                  <div
                    key={pt.date || idx}
                    className="flex-1 flex flex-col items-center group relative h-full justify-end"
                    onMouseEnter={() => setHoveredPoint(pt)}
                    onMouseLeave={() => setHoveredPoint(null)}
                  >
                    {/* Tooltip on Hover */}
                    {isHovered && (
                      <div className="absolute -top-12 z-20 px-3 py-1.5 rounded-xl bg-gray-950 text-white text-[10px] font-bold whitespace-nowrap shadow-xl border border-gray-800 animate-in fade-in zoom-in-95 pointer-events-none">
                        <div className="text-gray-400 font-normal">{pt.label || pt.date}</div>
                        <div className="text-brand-400">
                          {chartMetric === 'revenue' ? `$${pt.revenue.toFixed(2)}` : `${pt.orders} orders`}
                        </div>
                      </div>
                    )}

                    {/* Bar Pill */}
                    <div
                      style={{ height: `${heightPercent}%` }}
                      className={cn(
                        "w-full max-w-[28px] rounded-t-lg transition-all duration-300",
                        val > 0
                          ? (isHovered 
                              ? "bg-brand-500 dark:bg-brand-400 shadow-md shadow-brand-500/30" 
                              : "bg-brand-600/80 hover:bg-brand-500 dark:bg-brand-500/70")
                          : "bg-gray-100 dark:bg-gray-800/40"
                      )}
                    />
                  </div>
                );
              })}
            </div>
          )}

          {/* Chart X-Axis Labels */}
          {chartSeries.length > 0 && (
            <div className="flex justify-between items-center text-[10px] text-gray-400 pt-2 px-2">
              <span>{chartSeries[0]?.label || chartSeries[0]?.date}</span>
              {chartSeries.length > 2 && (
                <span>{chartSeries[Math.floor(chartSeries.length / 2)]?.label}</span>
              )}
              <span>{chartSeries[chartSeries.length - 1]?.label || chartSeries[chartSeries.length - 1]?.date}</span>
            </div>
          )}
        </div>
      </div>

      {/* Grid: Category Breakdown & Top Products */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Category Revenue Share */}
        <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-600" />
              Category Revenue Share
            </h3>
            <span className="text-xs text-gray-400">{categories.length} categories active</span>
          </div>

          {categories.length === 0 ? (
            <div className="py-12 text-center text-xs text-gray-400">
              No category sales recorded in this period.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Stacked Visual Bar */}
              <div className="h-4 w-full rounded-full overflow-hidden flex bg-gray-100 dark:bg-gray-800">
                {categories.map((cat, i) => {
                  const colors = [
                    'bg-brand-600', 'bg-purple-600', 'bg-blue-600', 
                    'bg-emerald-600', 'bg-amber-600', 'bg-rose-600'
                  ];
                  return (
                    <div
                      key={cat.category_id}
                      style={{ width: `${Math.max(2, cat.share)}%` }}
                      className={colors[i % colors.length]}
                      title={`${cat.category_name}: ${cat.share}%`}
                    />
                  );
                })}
              </div>

              {/* Category Breakdown Table */}
              <div className="divide-y divide-gray-100 dark:divide-gray-800/60 text-xs">
                {categories.map((cat, i) => (
                  <div key={cat.category_id} className="py-2.5 flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-brand-600" />
                      <span className="font-bold text-gray-900 dark:text-white">
                        {cat.category_name}
                      </span>
                      <span className="text-[11px] text-gray-400">
                        ({cat.units_sold} units)
                      </span>
                    </div>

                    <div className="text-right">
                      <span className="font-bold text-gray-900 dark:text-white block font-mono">
                        ${cat.revenue.toFixed(2)}
                      </span>
                      <span className="text-[10px] text-gray-400 font-mono">
                        {cat.share}% share
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Top Performing Best Sellers */}
        <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
              <Award className="w-4 h-4 text-amber-500" />
              Best-Selling Merchandise
            </h3>
            <Link
              to="/admin/products"
              className="text-xs font-bold text-brand-600 dark:text-brand-400 hover:underline flex items-center gap-1"
            >
              View Catalog <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>

          {topProducts.length === 0 ? (
            <div className="py-12 text-center text-xs text-gray-400">
              No top products recorded in this period.
            </div>
          ) : (
            <div className="divide-y divide-gray-100 dark:divide-gray-800/60 text-xs">
              {topProducts.map((prod, idx) => (
                <div key={prod.id} className="py-3 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="font-black text-xs text-gray-400 w-4">
                      #{idx + 1}
                    </span>
                    <img
                      src={prod.image}
                      alt={prod.name}
                      className="w-10 h-10 rounded-xl object-cover bg-gray-100 dark:bg-gray-800 shrink-0 border border-gray-200/60 dark:border-gray-800"
                    />
                    <div>
                      <h4 className="font-bold text-xs text-gray-900 dark:text-white line-clamp-1">
                        {prod.name}
                      </h4>
                      <span className="text-[11px] text-gray-400">
                        {prod.category} • ${prod.price.toFixed(2)}
                      </span>
                    </div>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="font-mono font-bold text-xs text-emerald-600 block">
                      ${prod.revenue.toFixed(2)}
                    </span>
                    <span className="text-[10px] text-gray-400 font-mono">
                      {prod.units_sold} sold
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Lower Row: Payment Methods & Recent Transactions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Payment Methods */}
        <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
          <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
            <CreditCard className="w-4 h-4 text-blue-600" />
            Payment Methods
          </h3>

          <div className="space-y-3 text-xs">
            {paymentMethods.map((pm) => (
              <div key={pm.method} className="space-y-1">
                <div className="flex justify-between font-medium">
                  <span className="text-gray-700 dark:text-gray-300 font-bold">
                    {pm.method}
                  </span>
                  <span className="font-mono text-gray-900 dark:text-white">
                    ${pm.volume.toFixed(2)} ({pm.share}%)
                  </span>
                </div>
                <div className="w-full h-2 rounded-full bg-gray-100 dark:bg-gray-800 overflow-hidden">
                  <div
                    style={{ width: `${Math.max(4, pm.share)}%` }}
                    className="h-full bg-blue-600 rounded-full"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent High-Value Transactions */}
        <div className="lg:col-span-2 p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-brand-600" />
              Latest Transactions Stream
            </h3>
            <Link
              to="/admin/orders"
              className="text-xs font-bold text-brand-600 dark:text-brand-400 hover:underline flex items-center gap-1"
            >
              All Orders <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="divide-y divide-gray-100 dark:divide-gray-800/60 text-xs">
            {recentTransactions.map((tx) => (
              <div key={tx.id} className="py-2.5 flex items-center justify-between gap-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-gray-900 dark:text-white">
                      #{tx.order_number}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300">
                      {tx.status}
                    </span>
                  </div>
                  <span className="text-[11px] text-gray-400 block">
                    {tx.customer_name} • {tx.payment_method?.toUpperCase()}
                  </span>
                </div>

                <div className="text-right">
                  <span className="font-mono font-black text-xs text-gray-900 dark:text-white block">
                    ${tx.total_amount.toFixed(2)}
                  </span>
                  <span className="text-[10px] text-gray-400">
                    {tx.created_at ? new Date(tx.created_at).toLocaleDateString(undefined, { dateStyle: 'short' }) : 'Recent'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

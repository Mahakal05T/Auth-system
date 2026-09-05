
import { useState, useEffect } from 'react';
import { adminInventoryService } from '../../services/api';
import { 
  AlertTriangle, CheckCircle, Package, Search, 
  History, Plus, Minus, ArrowUpDown, Loader2, X, ChevronLeft, ChevronRight, Layers 
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function AdminInventoryPage() {
  const [activeTab, setActiveTab] = useState('OVERVIEW'); // 'OVERVIEW' | 'LOGS'

  // Overview states
  const [items, setItems] = useState([]);
  const [metrics, setMetrics] = useState({ total_products: 0, low_stock_count: 0, out_of_stock_count: 0, total_units: 0 });
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [stockStatus, setStockStatus] = useState('all');

  // Logs states
  const [logs, setLogs] = useState([]);
  const [logsTotal, setLogsTotal] = useState(0);
  const [logsPage, setLogsPage] = useState(1);
  const [logsTotalPages, setLogsTotalPages] = useState(1);
  const [isLoadingLogs, setIsLoadingLogs] = useState(false);

  // Adjustment Modal
  const [adjustingItem, setAdjustingItem] = useState(null);
  const [adjustType, setAdjustType] = useState('ADD'); // 'ADD' | 'SET'
  const [adjustQty, setAdjustQty] = useState('');
  const [adjustReason, setAdjustReason] = useState('Warehouse replenishment');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchInventory = async (currPage = page) => {
    try {
      setIsLoading(true);
      const res = await adminInventoryService.getInventory({
        q: searchQuery,
        stock_status: stockStatus,
        page: currPage,
        limit: 10
      });
      setItems(res.items || []);
      setMetrics(res.metrics || { total_products: 0, low_stock_count: 0, out_of_stock_count: 0, total_units: 0 });
      setTotal(res.total || 0);
      setPage(res.page || 1);
      setTotalPages(res.total_pages || 1);
    } catch (err) {
      console.warn('Failed to load inventory:', err);
      toast.error('Failed to load warehouse inventory');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchLogs = async (currPage = logsPage) => {
    try {
      setIsLoadingLogs(true);
      const res = await adminInventoryService.getLogs({
        page: currPage,
        limit: 15
      });
      setLogs(res.logs || []);
      setLogsTotal(res.total || 0);
      setLogsPage(res.page || 1);
      setLogsTotalPages(res.total_pages || 1);
    } catch (err) {
      console.warn('Failed to load audit logs:', err);
      toast.error('Failed to load inventory logs');
    } finally {
      setIsLoadingLogs(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'OVERVIEW') {
      const timer = setTimeout(() => {
        fetchInventory(1);
      }, 250);
      return () => clearTimeout(timer);
    } else {
      fetchLogs(1);
    }
  }, [activeTab, searchQuery, stockStatus]);

  const handleOpenAdjustModal = (item) => {
    setAdjustingItem(item);
    setAdjustType('ADD');
    setAdjustQty('10');
    setAdjustReason('Warehouse replenishment');
  };

  const handleSaveAdjustment = async (e) => {
    e.preventDefault();
    if (!adjustQty) {
      toast.error('Please specify adjustment quantity');
      return;
    }

    try {
      setIsSubmitting(true);
      const qtyNum = parseInt(adjustQty, 10);
      const res = await adminInventoryService.adjustStock({
        product_id: adjustingItem.id,
        adjustment_type: adjustType,
        quantity: qtyNum,
        reason: adjustReason.trim()
      });

      toast.success(res.message || 'Stock level updated');
      setAdjustingItem(null);
      fetchInventory(page);
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to adjust stock';
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">Inventory Management</h1>
          <p className="text-xs text-gray-500 mt-1">
            Real-time warehouse stock controls, low-stock thresholds, and replenishment audit logs
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center gap-1.5 p-1 rounded-2xl bg-gray-100 dark:bg-gray-800/60 border border-gray-200/60 dark:border-gray-700/60 text-xs self-start sm:self-auto">
          <button
            onClick={() => setActiveTab('OVERVIEW')}
            className={`px-3.5 py-1.5 rounded-xl font-bold transition-all flex items-center gap-1.5 ${
              activeTab === 'OVERVIEW'
                ? 'bg-white dark:bg-gray-900 text-brand-600 shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <Package className="w-3.5 h-3.5" /> Stock Levels
          </button>
          <button
            onClick={() => setActiveTab('LOGS')}
            className={`px-3.5 py-1.5 rounded-xl font-bold transition-all flex items-center gap-1.5 ${
              activeTab === 'LOGS'
                ? 'bg-white dark:bg-gray-900 text-brand-600 shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5" /> Audit History
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider block">Total SKUs</span>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-1">{metrics.total_products}</div>
        </div>

        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-amber-500 uppercase tracking-wider block">Low Stock (&le;10)</span>
          <div className="text-2xl font-black text-amber-600 mt-1">{metrics.low_stock_count}</div>
        </div>

        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-rose-500 uppercase tracking-wider block">Out of Stock</span>
          <div className="text-2xl font-black text-rose-600 mt-1">{metrics.out_of_stock_count}</div>
        </div>

        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-emerald-500 uppercase tracking-wider block">Units In Stock</span>
          <div className="text-2xl font-black text-emerald-600 mt-1">{metrics.total_units}</div>
        </div>
      </div>

      {activeTab === 'OVERVIEW' ? (
        <div className="space-y-4">
          {/* Search & Filter Bar */}
          <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="relative flex-1 w-full max-w-md">
              <Search className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search products by title or SKU..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-2xl bg-gray-100 dark:bg-gray-800/60 border border-gray-200/60 dark:border-gray-700/60 text-xs">
              {[
                { id: 'all', label: 'All' },
                { id: 'low', label: 'Low Stock' },
                { id: 'out', label: 'Out of Stock' },
                { id: 'healthy', label: 'Healthy' }
              ].map((st) => (
                <button
                  key={st.id}
                  onClick={() => setStockStatus(st.id)}
                  className={`px-3 py-1.5 rounded-xl font-bold capitalize transition-all ${
                    stockStatus === st.id
                      ? 'bg-white dark:bg-gray-900 text-brand-600 shadow-xs'
                      : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
                  }`}
                >
                  {st.label}
                </button>
              ))}
            </div>
          </div>

          {/* Stock Table */}
          <div className="rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs overflow-hidden">
            {isLoading ? (
              <div className="py-20 text-center flex flex-col items-center justify-center space-y-3">
                <Loader2 className="w-8 h-8 text-brand-600 animate-spin" />
                <p className="text-xs text-gray-500">Checking inventory levels...</p>
              </div>
            ) : items.length === 0 ? (
              <div className="py-16 text-center space-y-3">
                <Package className="w-10 h-10 text-gray-400 mx-auto" />
                <p className="text-sm font-bold text-gray-900 dark:text-white">No products found</p>
                <p className="text-xs text-gray-500">Try adjusting your search query or status filter</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-gray-50 dark:bg-gray-800/50 border-b border-gray-100 dark:border-gray-800 text-gray-500">
                    <tr>
                      <th className="py-3 px-4 font-bold">Product</th>
                      <th className="py-3 px-4 font-bold">SKU</th>
                      <th className="py-3 px-4 font-bold">Category</th>
                      <th className="py-3 px-4 font-bold">Current Stock</th>
                      <th className="py-3 px-4 font-bold">Threshold Status</th>
                      <th className="py-3 px-4 font-bold text-right">Adjustment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                    {items.map((it) => (
                      <tr key={it.id} className="hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors">
                        <td className="py-3.5 px-4 flex items-center gap-3">
                          <img
                            src={it.image}
                            alt={it.name}
                            className="w-10 h-10 rounded-xl object-cover bg-gray-100 dark:bg-gray-800 shrink-0 border border-gray-200/50 dark:border-gray-700"
                          />
                          <span className="font-bold text-gray-900 dark:text-white max-w-xs truncate block">
                            {it.name}
                          </span>
                        </td>

                        <td className="py-3.5 px-4 font-mono text-[11px] text-gray-500">
                          {it.sku}
                        </td>

                        <td className="py-3.5 px-4 text-gray-500">
                          {it.category_name}
                        </td>

                        <td className="py-3.5 px-4">
                          <span className="font-black text-sm text-gray-900 dark:text-white">
                            {it.stock} <span className="text-xs font-normal text-gray-400">units</span>
                          </span>
                        </td>

                        <td className="py-3.5 px-4">
                          {it.stock === 0 ? (
                            <span className="px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-rose-100 text-rose-800 dark:bg-rose-950/40 dark:text-rose-300 inline-flex items-center gap-1 border border-rose-200 dark:border-rose-800/40">
                              <AlertTriangle className="w-3 h-3" /> Out of Stock
                            </span>
                          ) : it.stock <= 10 ? (
                            <span className="px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300 inline-flex items-center gap-1 border border-amber-200 dark:border-amber-800/40">
                              <AlertTriangle className="w-3 h-3" /> Low Stock
                            </span>
                          ) : (
                            <span className="px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300 inline-flex items-center gap-1 border border-emerald-200 dark:border-emerald-800/40">
                              <CheckCircle className="w-3 h-3" /> Healthy
                            </span>
                          )}
                        </td>

                        <td className="py-3.5 px-4 text-right">
                          <button
                            onClick={() => handleOpenAdjustModal(it)}
                            className="px-3 py-1.5 rounded-xl border border-gray-300 dark:border-gray-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 hover:text-brand-600 text-xs font-bold transition-colors inline-flex items-center gap-1"
                          >
                            <ArrowUpDown className="w-3.5 h-3.5" /> Adjust Stock
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="p-4 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between text-xs text-gray-500">
                <span>
                  Page {page} of {totalPages} ({total} SKUs)
                </span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={page <= 1}
                    onClick={() => fetchInventory(page - 1)}
                    className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <button
                    disabled={page >= totalPages}
                    onClick={() => fetchInventory(page + 1)}
                    className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Audit History Table */
        <div className="rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs overflow-hidden">
          {isLoadingLogs ? (
            <div className="py-20 text-center flex flex-col items-center justify-center space-y-3">
              <Loader2 className="w-8 h-8 text-brand-600 animate-spin" />
              <p className="text-xs text-gray-500">Loading inventory audit trails...</p>
            </div>
          ) : logs.length === 0 ? (
            <div className="py-16 text-center space-y-3">
              <History className="w-10 h-10 text-gray-400 mx-auto" />
              <p className="text-sm font-bold text-gray-900 dark:text-white">No inventory logs recorded</p>
              <p className="text-xs text-gray-500">Audit logs will appear when products are purchased, restocked, or adjusted.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-50 dark:bg-gray-800/50 border-b border-gray-100 dark:border-gray-800 text-gray-500">
                  <tr>
                    <th className="py-3 px-4 font-bold">Product</th>
                    <th className="py-3 px-4 font-bold">Event Type</th>
                    <th className="py-3 px-4 font-bold">Quantity Delta</th>
                    <th className="py-3 px-4 font-bold">Remaining Stock</th>
                    <th className="py-3 px-4 font-bold">Reason / Notes</th>
                    <th className="py-3 px-4 font-bold text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {logs.map((lg) => (
                    <tr key={lg.id} className="hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-bold text-gray-900 dark:text-white block">{lg.product_name}</span>
                        <span className="text-[11px] font-mono text-gray-400">{lg.sku}</span>
                      </td>

                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded-full font-mono text-[10px] font-bold bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 uppercase">
                          {lg.change_type}
                        </span>
                      </td>

                      <td className="py-3 px-4">
                        <span className={`font-mono font-black ${
                          lg.quantity_changed > 0 ? 'text-emerald-600' : lg.quantity_changed < 0 ? 'text-rose-600' : 'text-gray-500'
                        }`}>
                          {lg.quantity_changed > 0 ? `+${lg.quantity_changed}` : lg.quantity_changed}
                        </span>
                      </td>

                      <td className="py-3 px-4 font-black text-gray-900 dark:text-white">
                        {lg.remaining_stock} units
                      </td>

                      <td className="py-3 px-4 text-gray-500 max-w-xs truncate">
                        {lg.notes || '—'}
                      </td>

                      <td className="py-3 px-4 text-right font-mono text-[11px] text-gray-400">
                        {lg.created_at ? lg.created_at.slice(0, 16) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Logs Pagination */}
          {logsTotalPages > 1 && (
            <div className="p-4 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between text-xs text-gray-500">
              <span>
                Page {logsPage} of {logsTotalPages} ({logsTotal} logs)
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={logsPage <= 1}
                  onClick={() => fetchLogs(logsPage - 1)}
                  className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  disabled={logsPage >= logsTotalPages}
                  onClick={() => fetchLogs(logsPage + 1)}
                  className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Adjust Stock Modal */}
      {adjustingItem && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800 p-6 sm:p-8 max-w-md w-full space-y-5 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800">
              <div>
                <span className="text-[11px] font-bold text-brand-600 uppercase tracking-wider block">Inventory Adjustment</span>
                <h3 className="font-black text-lg text-gray-900 dark:text-white truncate max-w-xs mt-0.5">
                  {adjustingItem.name}
                </h3>
              </div>
              <button
                onClick={() => setAdjustingItem(null)}
                className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveAdjustment} className="space-y-4 text-xs">
              <div className="p-3 rounded-2xl bg-gray-50 dark:bg-gray-800/50 flex items-center justify-between">
                <span className="text-gray-500 font-medium">Current Stock Level:</span>
                <span className="font-black text-sm text-gray-900 dark:text-white">
                  {adjustingItem.stock} units
                </span>
              </div>

              <div>
                <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Adjustment Action</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setAdjustType('ADD')}
                    className={`py-2 px-3 rounded-xl font-bold border transition-all text-center ${
                      adjustType === 'ADD'
                        ? 'border-brand-600 bg-brand-50 dark:bg-brand-950/40 text-brand-600'
                        : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400'
                    }`}
                  >
                    Add / Deduct Units
                  </button>
                  <button
                    type="button"
                    onClick={() => setAdjustType('SET')}
                    className={`py-2 px-3 rounded-xl font-bold border transition-all text-center ${
                      adjustType === 'SET'
                        ? 'border-brand-600 bg-brand-50 dark:bg-brand-950/40 text-brand-600'
                        : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400'
                    }`}
                  >
                    Set Exact Count
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">
                  {adjustType === 'ADD' ? 'Quantity to Add (Use negative to deduct)' : 'New Total Stock Count'} *
                </label>
                <input
                  type="number"
                  required
                  value={adjustQty}
                  onChange={(e) => setAdjustQty(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white font-mono text-sm focus:outline-none focus:border-brand-500"
                />
              </div>

              <div>
                <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Reason / Reference Notes *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Shipment arrival PO#4912, Physical inventory audit"
                  value={adjustReason}
                  onChange={(e) => setAdjustReason(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-gray-100 dark:border-gray-800">
                <button
                  type="button"
                  onClick={() => setAdjustingItem(null)}
                  className="px-4 py-2.5 rounded-xl border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold transition-colors disabled:opacity-60 shadow-xs"
                >
                  {isSubmitting ? 'Updating...' : 'Confirm Stock Adjustment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

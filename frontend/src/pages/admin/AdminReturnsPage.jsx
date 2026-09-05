import { useState, useEffect } from 'react';
import { 
  RotateCcw, Package, CheckCircle2, AlertCircle, 
  Clock, DollarSign, Search, Filter, RefreshCw, 
  ExternalLink, ShieldAlert, ArrowRight, Copy, Check, 
  Truck, X, FileText, ChevronLeft, ChevronRight
} from 'lucide-react';
import { adminReturnService } from '../../services/api';
import { toast } from 'react-hot-toast';
import { cn } from '../../utils/helpers';
import { Link } from 'react-router-dom';

const STATUS_CONFIG = {
  REQUESTED: {
    label: 'Pending Review',
    color: 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800/50',
    icon: Clock
  },
  APPROVED: {
    label: 'Return Authorized',
    color: 'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-800/50',
    icon: Truck
  },
  ITEM_RECEIVED: {
    label: 'Package Received',
    color: 'bg-purple-100 dark:bg-purple-950/60 text-purple-800 dark:text-purple-300 border-purple-300 dark:border-purple-800/50',
    icon: Package
  },
  REFUNDED: {
    label: 'Refund Completed',
    color: 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800/50',
    icon: CheckCircle2
  },
  REJECTED: {
    label: 'Dispute Rejected',
    color: 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800/50',
    icon: AlertCircle
  },
};

export default function AdminReturnsPage() {
  const [returnsList, setReturnsList] = useState([]);
  const [stats, setStats] = useState({
    total_returns: 0,
    pending_requests: 0,
    active_returns: 0,
    refunded_count: 0,
    total_refunded_amount: 0,
    rejected_count: 0
  });
  const [loading, setLoading] = useState(true);

  // Filter & Pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);

  // Inspect / Action Modal State
  const [selectedReturn, setSelectedReturn] = useState(null);
  const [adminNotesInput, setAdminNotesInput] = useState('');
  const [customRefundAmount, setCustomRefundAmount] = useState('');
  const [restockCheckbox, setRestockCheckbox] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  const fetchReturns = async (currPage = page) => {
    try {
      setLoading(true);
      const params = {
        page: currPage,
        limit: 10
      };
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (statusFilter !== 'ALL') params.status = statusFilter;

      const res = await adminReturnService.getReturns(params);
      if (res.success) {
        setReturnsList(res.returns || []);
        if (res.stats) setStats(res.stats);
        setPage(res.page || 1);
        setTotalPages(res.total_pages || 1);
        setTotalItems(res.total || 0);
      }
    } catch (err) {
      console.error('Error fetching returns:', err);
      toast.error('Failed to load return requests');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchReturns(1);
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery, statusFilter]);

  const handleOpenProcessModal = (ret) => {
    setSelectedReturn(ret);
    setAdminNotesInput(ret.admin_notes || '');
    setCustomRefundAmount(ret.refund_amount ? String(ret.refund_amount) : '');
    setRestockCheckbox(true);
  };

  const handleUpdateStatus = async (newStatus) => {
    if (!selectedReturn) return;

    try {
      setIsProcessing(true);
      const payload = {
        status: newStatus,
        admin_notes: adminNotesInput.trim(),
        refund_amount: customRefundAmount ? parseFloat(customRefundAmount) : selectedReturn.refund_amount,
        restock_inventory: restockCheckbox
      };

      const res = await adminReturnService.updateReturnStatus(selectedReturn.id, payload);
      toast.success(res.message);
      setSelectedReturn(null);
      fetchReturns(page);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to update return');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success('RMA Code copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <RotateCcw className="w-7 h-7 text-brand-600 dark:text-brand-400" />
            Returns, Refunds & Order Disputes
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Authorize return merchandise requests (RMA), track warehouse arrivals, issue payment refunds, and resolve claims.
          </p>
        </div>

        <button
          onClick={() => fetchReturns(page)}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-xs font-bold rounded-2xl shadow-xs text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors self-start sm:self-auto cursor-pointer"
        >
          <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
          Refresh Requests
        </button>
      </div>

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 sm:gap-4">
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Claims</span>
            <div className="w-8 h-8 rounded-xl bg-blue-50 dark:bg-blue-950/40 text-blue-600 flex items-center justify-center">
              <RotateCcw className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.total_returns}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Total recorded disputes</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Pending Review</span>
            <div className="w-8 h-8 rounded-xl bg-amber-50 dark:bg-amber-950/40 text-amber-600 flex items-center justify-center">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-amber-600 mt-2">
            {stats.pending_requests}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Requires action</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">In-Transit / Authorized</span>
            <div className="w-8 h-8 rounded-xl bg-purple-50 dark:bg-purple-950/40 text-purple-600 flex items-center justify-center">
              <Truck className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-purple-600 mt-2">
            {stats.active_returns}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Awaiting warehouse</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Refunded</span>
            <div className="w-8 h-8 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 flex items-center justify-center">
              <DollarSign className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-emerald-600 mt-2">
            ${stats.total_refunded_amount.toFixed(2)}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">
            Across {stats.refunded_count} orders
          </span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Rejected Claims</span>
            <div className="w-8 h-8 rounded-xl bg-rose-50 dark:bg-rose-950/40 text-rose-600 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-rose-600 mt-2">
            {stats.rejected_count}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Disallowed returns</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by RMA, Order #, customer name, reason..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
          />
        </div>

        {/* Status Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto pb-1 md:pb-0 bg-gray-100 dark:bg-gray-800 p-1 rounded-2xl text-xs font-medium text-gray-600 dark:text-gray-300">
          {[
            { id: 'ALL', label: 'All' },
            { id: 'REQUESTED', label: 'Pending Review' },
            { id: 'APPROVED', label: 'Authorized' },
            { id: 'ITEM_RECEIVED', label: 'Received' },
            { id: 'REFUNDED', label: 'Refunded' },
            { id: 'REJECTED', label: 'Rejected' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setStatusFilter(tab.id)}
              className={cn(
                "px-3 py-1.5 rounded-xl transition-all whitespace-nowrap",
                statusFilter === tab.id 
                  ? "bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-bold shadow-xs" 
                  : "hover:text-gray-900 dark:hover:text-white"
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Returns Table */}
      <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800 overflow-hidden shadow-xs">
        {loading && returnsList.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-xs">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-brand-600" />
            Loading return requests...
          </div>
        ) : returnsList.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <RotateCcw className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-700" />
            <h3 className="text-sm font-bold text-gray-900 dark:text-white">No return claims found</h3>
            <p className="text-xs text-gray-500 max-w-sm mx-auto">
              Any customer return or order dispute initiated from delivered orders will appear here for operational processing.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 dark:bg-gray-950/50 text-gray-500 border-b border-gray-200 dark:border-gray-800 uppercase tracking-wider text-[10px] font-bold">
                <tr>
                  <th className="py-3.5 px-4">RMA & Order</th>
                  <th className="py-3.5 px-4">Customer</th>
                  <th className="py-3.5 px-4">Claim Reason</th>
                  <th className="py-3.5 px-4">Refund Amount</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4">Requested Date</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800/60 font-normal">
                {returnsList.map((ret) => {
                  const cfg = STATUS_CONFIG[ret.status] || STATUS_CONFIG.REQUESTED;
                  const Icon = cfg.icon;

                  return (
                    <tr key={ret.id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/30 transition-colors">
                      {/* RMA & Order Link */}
                      <td className="py-3.5 px-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono font-black text-xs text-gray-900 dark:text-white">
                              {ret.return_number}
                            </span>
                            <button
                              onClick={() => handleCopy(ret.return_number, ret.id)}
                              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 p-0.5"
                              title="Copy RMA"
                            >
                              {copiedId === ret.id ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>

                          <Link
                            to={`/admin/orders?search=${ret.order_number}`}
                            className="text-[11px] font-bold text-brand-600 dark:text-brand-400 hover:underline flex items-center gap-1"
                          >
                            <span>#{ret.order_number}</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </Link>
                        </div>
                      </td>

                      {/* Customer */}
                      <td className="py-3.5 px-4">
                        <div>
                          <div className="font-bold text-xs text-gray-900 dark:text-white">
                            {ret.customer_name}
                          </div>
                          <div className="text-[11px] text-gray-400 truncate max-w-xs">
                            {ret.customer_email}
                          </div>
                        </div>
                      </td>

                      {/* Reason */}
                      <td className="py-3.5 px-4 max-w-xs">
                        <div>
                          <span className="font-bold text-xs text-gray-800 dark:text-gray-200 line-clamp-1">
                            {ret.reason}
                          </span>
                          {ret.customer_notes && (
                            <p className="text-[11px] text-gray-400 italic line-clamp-1 mt-0.5">
                              "{ret.customer_notes}"
                            </p>
                          )}
                        </div>
                      </td>

                      {/* Amount */}
                      <td className="py-3.5 px-4">
                        <div>
                          <span className="font-mono font-black text-xs text-gray-900 dark:text-white">
                            ${ret.refund_amount.toFixed(2)}
                          </span>
                          <span className="text-[10px] text-gray-400 block uppercase font-mono">
                            {ret.refund_method.replace('_', ' ')}
                          </span>
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        <span className={cn(
                          "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wide border",
                          cfg.color
                        )}>
                          <Icon className="w-3 h-3" />
                          {cfg.label}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="py-3.5 px-4 text-gray-500 text-[11px]">
                        {ret.created_at ? new Date(ret.created_at).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'Recent'}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => handleOpenProcessModal(ret)}
                          className="px-3 py-1.5 rounded-xl bg-gray-900 dark:bg-white text-white dark:text-gray-900 hover:bg-brand-600 dark:hover:bg-brand-600 dark:hover:text-white text-xs font-bold transition-colors cursor-pointer"
                        >
                          Process RMA
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-xs">
          <span className="text-gray-500">
            Showing Page <strong>{page}</strong> of <strong>{totalPages}</strong> ({totalItems} total requests)
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchReturns(page - 1)}
              disabled={page <= 1}
              className="p-2 rounded-xl border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => fetchReturns(page + 1)}
              disabled={page >= totalPages}
              className="p-2 rounded-xl border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* RMA Process Decision Modal */}
      {selectedReturn && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl w-full max-w-lg shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <RotateCcw className="w-5 h-5 text-brand-600" />
                <h3 className="font-black text-sm text-gray-900 dark:text-white">
                  RMA Decision: {selectedReturn.return_number}
                </h3>
              </div>
              <button
                onClick={() => setSelectedReturn(null)}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-4 overflow-y-auto flex-1 text-xs">
              {/* Claim Overview Box */}
              <div className="p-4 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-gray-500 font-medium">Order Number</span>
                  <span className="font-mono font-bold text-gray-900 dark:text-white">
                    #{selectedReturn.order_number}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500 font-medium">Customer</span>
                  <span className="font-bold text-gray-900 dark:text-white">
                    {selectedReturn.customer_name} ({selectedReturn.customer_email})
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500 font-medium">Claim Reason</span>
                  <span className="font-bold text-brand-600 dark:text-brand-400">
                    {selectedReturn.reason}
                  </span>
                </div>
                {selectedReturn.customer_notes && (
                  <div className="pt-2 border-t border-gray-200/60 dark:border-gray-800">
                    <span className="text-gray-400 block text-[11px] mb-0.5">Customer Explanation:</span>
                    <p className="text-gray-700 dark:text-gray-300 italic">
                      "{selectedReturn.customer_notes}"
                    </p>
                  </div>
                )}
              </div>

              {/* Current Status Banner */}
              <div className="flex items-center justify-between p-3 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
                <span className="font-bold text-gray-500">Current Status:</span>
                <span className={cn(
                  "px-2.5 py-1 rounded-full text-[10px] font-bold border",
                  STATUS_CONFIG[selectedReturn.status]?.color || STATUS_CONFIG.REQUESTED.color
                )}>
                  {STATUS_CONFIG[selectedReturn.status]?.label || selectedReturn.status}
                </span>
              </div>

              {/* Refund Parameters */}
              <div className="space-y-3 pt-2">
                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Refund Amount ($)
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    value={customRefundAmount}
                    onChange={(e) => setCustomRefundAmount(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white font-mono font-bold focus:outline-none focus:border-brand-500"
                  />
                  <span className="text-[10px] text-gray-400 mt-0.5 block">
                    Original order total was ${selectedReturn.order_total?.toFixed(2)}
                  </span>
                </div>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={restockCheckbox}
                    onChange={(e) => setRestockCheckbox(e.target.checked)}
                    className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                  />
                  <span className="font-bold text-gray-800 dark:text-gray-200">
                    Automatically restock returned items into product inventory
                  </span>
                </label>

                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Internal Operations Notes / Customer Feedback
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Provide notes, instructions or reason for rejection..."
                    value={adminNotesInput}
                    onChange={(e) => setAdminNotesInput(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 leading-relaxed"
                  />
                </div>
              </div>

              {/* Workflow Pipeline Action Buttons */}
              <div className="pt-4 border-t border-gray-100 dark:border-gray-800 space-y-2">
                <span className="font-bold text-gray-500 text-[10px] uppercase tracking-wider block">
                  Select Resolution Action:
                </span>

                <div className="grid grid-cols-2 gap-2">
                  {/* Approve Return */}
                  <button
                    type="button"
                    disabled={isProcessing || selectedReturn.status === 'APPROVED'}
                    onClick={() => handleUpdateStatus('APPROVED')}
                    className="p-2.5 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 font-bold hover:bg-blue-100 transition-colors disabled:opacity-40 text-center"
                  >
                    1. Authorize RMA
                  </button>

                  {/* Mark Received */}
                  <button
                    type="button"
                    disabled={isProcessing || selectedReturn.status === 'ITEM_RECEIVED'}
                    onClick={() => handleUpdateStatus('ITEM_RECEIVED')}
                    className="p-2.5 rounded-xl border border-purple-200 dark:border-purple-900/60 bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 font-bold hover:bg-purple-100 transition-colors disabled:opacity-40 text-center"
                  >
                    2. Mark Received
                  </button>

                  {/* Issue Refund */}
                  <button
                    type="button"
                    disabled={isProcessing || selectedReturn.status === 'REFUNDED'}
                    onClick={() => handleUpdateStatus('REFUNDED')}
                    className="p-2.5 rounded-xl border border-emerald-200 dark:border-emerald-900/60 bg-emerald-600 text-white font-bold hover:bg-emerald-700 transition-colors disabled:opacity-40 text-center shadow-xs"
                  >
                    3. Issue Full Refund ($)
                  </button>

                  {/* Reject Return */}
                  <button
                    type="button"
                    disabled={isProcessing || selectedReturn.status === 'REJECTED'}
                    onClick={() => handleUpdateStatus('REJECTED')}
                    className="p-2.5 rounded-xl border border-rose-200 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 font-bold hover:bg-rose-100 transition-colors disabled:opacity-40 text-center"
                  >
                    Deny / Reject Claim
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

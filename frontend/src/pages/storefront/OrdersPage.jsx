import { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { orderService, returnService } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { 
  Package, ChevronRight, Truck, Clock, AlertTriangle, 
  CheckCircle2, XCircle, Ban, ArrowRight, Loader2, RotateCcw, X, Send 
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function OrdersPage() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  const [orders, setOrders] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [cancellingOrderId, setCancellingOrderId] = useState(null);

  // Return request modal state
  const [returnOrderModal, setReturnOrderModal] = useState(null);
  const [returnReason, setReturnReason] = useState('Defective / Doesn\'t work properly');
  const [returnDetails, setReturnDetails] = useState('');
  const [refundMethod, setRefundMethod] = useState('ORIGINAL_PAYMENT');
  const [isSubmittingReturn, setIsSubmittingReturn] = useState(false);

  const fetchOrders = async () => {
    try {
      setIsLoading(true);
      const list = await orderService.getMyOrders();
      setOrders(list);
    } catch (err) {
      console.warn('Could not fetch customer orders:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchOrders();
    } else {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  const handleCancelOrder = async (order) => {
    if (!window.confirm(`Are you sure you want to cancel Order #${order.order_number}? Items will be returned to store inventory.`)) {
      return;
    }

    try {
      setCancellingOrderId(order.id);
      const res = await orderService.cancelOrder(order.id);
      toast.success(res.message || `Order #${order.order_number} has been cancelled`);
      fetchOrders();
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to cancel order';
      toast.error(msg);
    } finally {
      setCancellingOrderId(null);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'DELIVERED':
        return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800/40';
      case 'RETURN_REQUESTED':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-950/50 dark:text-purple-300 border-purple-200 dark:border-purple-800/40';
      case 'RETURN_APPROVED':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/50 dark:text-blue-300 border-blue-200 dark:border-blue-800/40';
      case 'RETURN_RECEIVED':
        return 'bg-indigo-100 text-indigo-800 dark:bg-indigo-950/50 dark:text-indigo-300 border-indigo-200 dark:border-indigo-800/40';
      case 'REFUNDED':
        return 'bg-teal-100 text-teal-800 dark:bg-teal-950/50 dark:text-teal-300 border-teal-200 dark:border-teal-800/40';
      case 'SHIPPED':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/50 dark:text-blue-300 border-blue-200 dark:border-blue-800/40';
      case 'PROCESSING':
      case 'PLACED':
      case 'PENDING':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200 dark:border-amber-800/40';
      case 'CANCELLED':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/50 dark:text-rose-300 border-rose-200 dark:border-rose-800/40';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300';
    }
  };

  const handleOpenReturnModal = (order) => {
    setReturnOrderModal(order);
    setReturnReason('Defective / Doesn\'t work properly');
    setReturnDetails('');
    setRefundMethod('ORIGINAL_PAYMENT');
  };

  const handleSubmitReturn = async (e) => {
    e.preventDefault();
    if (!returnOrderModal) return;

    try {
      setIsSubmittingReturn(true);
      const res = await returnService.requestReturn({
        order_id: returnOrderModal.id,
        reason: returnReason,
        customer_notes: returnDetails.trim(),
        refund_method: refundMethod
      });
      toast.success(res.message);
      setReturnOrderModal(null);
      fetchOrders();
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to request return');
    } finally {
      setIsSubmittingReturn(false);
    }
  };

  const filteredOrders = orders.filter((o) => {
    if (filter === 'ACTIVE') return ['PLACED', 'PROCESSING', 'SHIPPED', 'PENDING'].includes(o.status);
    if (filter === 'DELIVERED') return o.status === 'DELIVERED';
    if (filter === 'CANCELLED') return o.status === 'CANCELLED';
    return true;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-gray-200 dark:border-gray-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <Package className="w-7 h-7 text-brand-600 shrink-0" />
            My Orders ({orders.length})
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Track parcels, review previous transactions, or manage order cancellations
          </p>
        </div>

        {/* Filter Tabs */}
        {orders.length > 0 && (
          <div className="flex items-center gap-1.5 p-1 rounded-2xl bg-gray-100 dark:bg-gray-800/60 border border-gray-200/60 dark:border-gray-700/60 text-xs self-start sm:self-auto">
            {['ALL', 'ACTIVE', 'DELIVERED', 'CANCELLED'].map((tab) => (
              <button
                key={tab}
                onClick={() => setFilter(tab)}
                className={`px-3 py-1.5 rounded-xl font-bold capitalize transition-all ${
                  filter === tab
                    ? 'bg-white dark:bg-gray-900 text-brand-600 shadow-xs'
                    : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
                }`}
              >
                {tab.toLowerCase()}
              </button>
            ))}
          </div>
        )}
      </div>

      {isLoading ? (
        <div className="py-20 text-center flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-brand-600 animate-spin" />
          <p className="text-xs text-gray-500">Retrieving your order history...</p>
        </div>
      ) : !isAuthenticated ? (
        <div className="text-center py-16 px-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4 shadow-xs">
          <Package className="w-12 h-12 text-gray-400 mx-auto" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Sign In to View Orders</h2>
          <p className="text-xs text-gray-500 max-w-sm mx-auto">
            Please log in to your account to review your purchase history and track active deliveries.
          </p>
          <Link
            to="/login?redirect=/orders"
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-full bg-brand-600 text-white font-bold text-xs shadow-md"
          >
            Sign In Now <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      ) : filteredOrders.length === 0 ? (
        <div className="text-center py-16 px-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4 shadow-xs">
          <div className="w-16 h-16 rounded-full bg-brand-50 dark:bg-brand-950/50 text-brand-600 flex items-center justify-center mx-auto">
            <Package className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">
            {orders.length === 0 ? 'No Orders Placed Yet' : 'No Orders In This Category'}
          </h2>
          <p className="text-xs sm:text-sm text-gray-500 max-w-sm mx-auto">
            {orders.length === 0
              ? 'You haven\'t placed any orders with us yet. Start exploring our catalog to find exciting offers!'
              : `You have no ${filter.toLowerCase()} orders.`}
          </p>
          <Link
            to="/products"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs transition-colors shadow-md shadow-brand-600/20"
          >
            Start Shopping <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredOrders.map((order) => (
            <div
              key={order.id}
              className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-5 shadow-xs hover:border-gray-300 dark:hover:border-gray-700 transition-all"
            >
              {/* Order Meta Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-100 dark:border-gray-800 text-xs">
                <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                  <span className="font-mono font-bold text-gray-900 dark:text-white text-sm">
                    {order.order_number}
                  </span>
                  <span className="text-gray-300 dark:text-gray-700">•</span>
                  <span className="text-gray-500">
                    {order.created_at ? new Date(order.created_at).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'Recently'}
                  </span>
                  <span className="text-gray-300 dark:text-gray-700 hidden sm:inline">•</span>
                  <span className="text-gray-500 capitalize hidden sm:inline">
                    Pay: <strong>{order.payment_method}</strong> ({order.payment_status})
                  </span>
                </div>

                <span className={`px-3 py-1 rounded-full font-bold text-[11px] uppercase tracking-wider border w-fit ${getStatusBadge(order.status)}`}>
                  {order.status}
                </span>
              </div>

              {/* Order Content Summary */}
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <img
                    src={order.primary_image}
                    alt="order item"
                    className="w-16 h-16 sm:w-20 sm:h-20 rounded-2xl object-cover bg-gray-100 dark:bg-gray-800 shrink-0 border border-gray-200/50 dark:border-gray-800"
                  />

                  <div className="space-y-1 text-xs">
                    <div className="font-bold text-sm text-gray-900 dark:text-white">
                      {order.total_items_count} {order.total_items_count === 1 ? 'item' : 'items'}
                    </div>
                    {order.items_preview && order.items_preview.length > 0 && (
                      <div className="text-gray-500 text-[11px] line-clamp-1 max-w-md">
                        {order.items_preview.join(', ')}
                      </div>
                    )}
                    <div className="text-gray-600 dark:text-gray-400 font-semibold pt-0.5">
                      Order Total: <strong className="text-gray-900 dark:text-white font-black text-sm">${order.total_amount.toFixed(2)}</strong>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto pt-2 md:pt-0 border-t md:border-t-0 border-gray-100 dark:border-gray-800 justify-end">
                  {order.can_cancel && (
                    <button
                      onClick={() => handleCancelOrder(order)}
                      disabled={cancellingOrderId === order.id}
                      className="px-3.5 py-2 rounded-xl border border-gray-300 dark:border-gray-700 text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40 text-xs font-bold transition-colors disabled:opacity-60 flex items-center gap-1.5 cursor-pointer"
                    >
                      <Ban className="w-3.5 h-3.5" />
                      {cancellingOrderId === order.id ? 'Cancelling...' : 'Cancel Order'}
                    </button>
                  )}

                  {order.status === 'DELIVERED' && (
                    <button
                      onClick={() => handleOpenReturnModal(order)}
                      className="px-3.5 py-2 rounded-xl border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 text-xs font-bold transition-colors flex items-center gap-1.5 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5 text-brand-600" />
                      Return / Refund
                    </button>
                  )}

                  {['RETURN_REQUESTED', 'RETURN_APPROVED', 'RETURN_RECEIVED'].includes(order.status) && (
                    <span className="px-3 py-1.5 rounded-xl bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/40 text-xs font-bold flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5" />
                      Return in Progress
                    </span>
                  )}

                  <Link
                    to={`/orders/${order.order_number}/track`}
                    className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white text-xs font-bold flex items-center gap-1.5 transition-colors shadow-xs"
                  >
                    <Truck className="w-3.5 h-3.5" /> Track Package
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Customer Return Request Modal */}
      {returnOrderModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl w-full max-w-md shadow-2xl overflow-hidden p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-100 dark:border-gray-800 pb-3">
              <div className="flex items-center gap-2">
                <RotateCcw className="w-5 h-5 text-brand-600" />
                <h3 className="font-black text-sm text-gray-900 dark:text-white">
                  Request Return & Refund
                </h3>
              </div>
              <button
                onClick={() => setReturnOrderModal(null)}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800 text-xs space-y-1">
              <div className="flex justify-between">
                <span className="text-gray-500">Order:</span>
                <span className="font-bold text-gray-900 dark:text-white font-mono">#{returnOrderModal.order_number}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Refund Amount:</span>
                <span className="font-bold text-gray-900 dark:text-white font-mono">${returnOrderModal.total_amount.toFixed(2)}</span>
              </div>
            </div>

            <form onSubmit={handleSubmitReturn} className="space-y-4 text-xs">
              <div>
                <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Reason for Return *
                </label>
                <select
                  value={returnReason}
                  onChange={(e) => setReturnReason(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                >
                  <option value="Defective / Doesn't work properly">Defective / Doesn't work properly</option>
                  <option value="Wrong item delivered">Wrong item delivered</option>
                  <option value="Item damaged during transit">Item damaged during transit</option>
                  <option value="Changed mind / No longer needed">Changed mind / No longer needed</option>
                  <option value="Size, color, or style issue">Size, color, or style issue</option>
                  <option value="Other reason">Other reason</option>
                </select>
              </div>

              <div>
                <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Preferred Refund Method
                </label>
                <select
                  value={refundMethod}
                  onChange={(e) => setRefundMethod(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                >
                  <option value="ORIGINAL_PAYMENT">Original Payment Method</option>
                  <option value="STORE_CREDIT">Store Credit Voucher (Instant)</option>
                </select>
              </div>

              <div>
                <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Additional Explanation (Optional)
                </label>
                <textarea
                  rows={3}
                  placeholder="Describe the issue with the item to expedite processing..."
                  value={returnDetails}
                  onChange={(e) => setReturnDetails(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 leading-relaxed"
                />
              </div>

              <div className="pt-3 border-t border-gray-100 dark:border-gray-800 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setReturnOrderModal(null)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingReturn}
                  className="px-5 py-2 rounded-xl text-xs font-bold bg-brand-600 hover:bg-brand-700 text-white shadow-md shadow-brand-600/20 disabled:opacity-50 inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  {isSubmittingReturn ? 'Submitting...' : 'Submit Claim'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

import { useState, useEffect } from 'react';
import { adminOrderService } from '../../services/api';
import { 
  Eye, Search, Truck, Clock, CheckCircle2, 
  XCircle, AlertTriangle, Package, Loader2, X, ChevronLeft, ChevronRight, User, MapPin, CreditCard 
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function AdminOrdersPage() {
  const [orders, setOrders] = useState([]);
  const [counts, setCounts] = useState({ total: 0, processing: 0, shipped: 0, delivered: 0, cancelled: 0 });
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('ALL');

  // Detail Modal
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  const fetchOrders = async (currPage = page) => {
    try {
      setIsLoading(true);
      const res = await adminOrderService.getOrders({
        q: searchQuery,
        status: selectedStatus,
        page: currPage,
        limit: 10
      });
      setOrders(res.orders || []);
      setCounts(res.counts || { total: 0, processing: 0, shipped: 0, delivered: 0, cancelled: 0 });
      setTotal(res.total || 0);
      setPage(res.page || 1);
      setTotalPages(res.total_pages || 1);
    } catch (err) {
      console.warn('Failed to load admin orders:', err);
      toast.error('Failed to load platform orders');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchOrders(1);
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery, selectedStatus]);

  const handleUpdateStatus = async (orderId, newStatus) => {
    try {
      setIsUpdatingStatus(true);
      const res = await adminOrderService.updateOrderStatus(orderId, newStatus);
      toast.success(res.message || `Order status updated to ${newStatus}`);
      fetchOrders(page);
      if (selectedOrder && selectedOrder.id === orderId) {
        setSelectedOrder(prev => ({ ...prev, status: newStatus, payment_status: res.payment_status || prev.payment_status }));
      }
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to update order status';
      toast.error(msg);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleOpenDetailModal = async (orderId) => {
    try {
      setIsLoadingDetail(true);
      setSelectedOrder(null);
      const detail = await adminOrderService.getOrderDetail(orderId);
      setSelectedOrder(detail);
    } catch (err) {
      toast.error('Failed to retrieve order details');
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'DELIVERED':
        return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300 border-emerald-200';
      case 'SHIPPED':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/40 dark:text-blue-300 border-blue-200';
      case 'PROCESSING':
      case 'PLACED':
      case 'PENDING':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300 border-amber-200';
      case 'CANCELLED':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/40 dark:text-rose-300 border-rose-200';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300 border-gray-200';
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">Customer Orders</h1>
        <p className="text-xs text-gray-500 mt-1">Review orders, manage fulfillment milestones, and handle customer requests</p>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider block">Total Orders</span>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-1">{counts.total}</div>
        </div>

        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-amber-500 uppercase tracking-wider block">In Processing</span>
          <div className="text-2xl font-black text-amber-600 mt-1">{counts.processing}</div>
        </div>

        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-blue-500 uppercase tracking-wider block">Shipped</span>
          <div className="text-2xl font-black text-blue-600 mt-1">{counts.shipped}</div>
        </div>

        <div className="p-4 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <span className="text-[11px] font-bold text-emerald-500 uppercase tracking-wider block">Delivered</span>
          <div className="text-2xl font-black text-emerald-600 mt-1">{counts.delivered}</div>
        </div>
      </div>

      {/* Search & Status Filter */}
      <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="relative flex-1 w-full max-w-md">
          <Search className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by Order #, Customer, or Email..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-2xl bg-gray-100 dark:bg-gray-800/60 border border-gray-200/60 dark:border-gray-700/60 text-xs">
          {['ALL', 'PROCESSING', 'SHIPPED', 'DELIVERED', 'CANCELLED'].map((st) => (
            <button
              key={st}
              onClick={() => setSelectedStatus(st)}
              className={`px-3 py-1.5 rounded-xl font-bold capitalize transition-all ${
                selectedStatus === st
                  ? 'bg-white dark:bg-gray-900 text-brand-600 shadow-xs'
                  : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              {st.toLowerCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Orders Table */}
      <div className="rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs overflow-hidden">
        {isLoading ? (
          <div className="py-20 text-center flex flex-col items-center justify-center space-y-3">
            <Loader2 className="w-8 h-8 text-brand-600 animate-spin" />
            <p className="text-xs text-gray-500">Loading orders...</p>
          </div>
        ) : orders.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <Package className="w-10 h-10 text-gray-400 mx-auto" />
            <p className="text-sm font-bold text-gray-900 dark:text-white">No orders match filter criteria</p>
            <p className="text-xs text-gray-500">Try changing your search term or status selection</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 dark:bg-gray-800/50 border-b border-gray-100 dark:border-gray-800 text-gray-500">
                <tr>
                  <th className="py-3 px-4 font-bold">Order Number</th>
                  <th className="py-3 px-4 font-bold">Customer</th>
                  <th className="py-3 px-4 font-bold">Date</th>
                  <th className="py-3 px-4 font-bold">Items</th>
                  <th className="py-3 px-4 font-bold">Total</th>
                  <th className="py-3 px-4 font-bold">Status</th>
                  <th className="py-3 px-4 font-bold text-right">Fulfillment</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                {orders.map((ord) => (
                  <tr key={ord.id} className="hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors">
                    <td className="py-3.5 px-4 font-mono font-bold text-gray-900 dark:text-white">
                      <button
                        onClick={() => handleOpenDetailModal(ord.id)}
                        className="hover:text-brand-600 hover:underline flex items-center gap-1.5"
                      >
                        {ord.order_number}
                      </button>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="font-bold text-gray-900 dark:text-white">{ord.customer}</div>
                      <div className="text-[11px] text-gray-400">{ord.email}</div>
                    </td>

                    <td className="py-3.5 px-4 text-gray-500">
                      {ord.date}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <img
                          src={ord.primary_image}
                          alt="item"
                          className="w-7 h-7 rounded-lg object-cover bg-gray-100 dark:bg-gray-800"
                        />
                        <span className="text-gray-600 dark:text-gray-300 font-medium">
                          {ord.items_count} {ord.items_count === 1 ? 'item' : 'items'}
                        </span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className="font-black text-gray-900 dark:text-white block">
                        ${ord.total.toFixed(2)}
                      </span>
                      <span className="text-[10px] text-gray-400 uppercase">
                        {ord.payment_method} • {ord.payment_status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${getStatusBadge(ord.status)}`}>
                        {ord.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-right space-x-2">
                      <select
                        value={ord.status}
                        onChange={(e) => handleUpdateStatus(ord.id, e.target.value)}
                        className="bg-transparent border border-gray-300 dark:border-gray-700 rounded-xl px-2.5 py-1.5 text-xs font-semibold text-gray-800 dark:text-gray-200 focus:outline-none focus:border-brand-500"
                      >
                        <option value="PLACED">PLACED</option>
                        <option value="PROCESSING">PROCESSING</option>
                        <option value="SHIPPED">SHIPPED</option>
                        <option value="DELIVERED">DELIVERED</option>
                        <option value="CANCELLED">CANCELLED</option>
                      </select>

                      <button
                        onClick={() => handleOpenDetailModal(ord.id)}
                        className="p-1.5 rounded-xl border border-gray-200 dark:border-gray-700 hover:text-brand-600 transition-colors inline-flex items-center"
                        title="View Full Order Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
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
              Page {page} of {totalPages} ({total} orders)
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => fetchOrders(page - 1)}
                className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => fetchOrders(page + 1)}
                className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Order Detail Modal */}
      {(selectedOrder || isLoadingDetail) && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800 p-6 sm:p-8 max-w-2xl w-full space-y-6 shadow-2xl animate-in zoom-in-95 duration-200 my-8">
            <div className="flex items-center justify-between pb-4 border-b border-gray-100 dark:border-gray-800">
              <div>
                <span className="text-[11px] font-bold text-brand-600 uppercase tracking-wider block">Order Details</span>
                <h3 className="font-black text-xl text-gray-900 dark:text-white font-mono mt-0.5">
                  {selectedOrder ? selectedOrder.order_number : 'Loading...'}
                </h3>
              </div>
              <button
                onClick={() => setSelectedOrder(null)}
                className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {isLoadingDetail || !selectedOrder ? (
              <div className="py-12 text-center space-y-2">
                <Loader2 className="w-6 h-6 text-brand-600 animate-spin mx-auto" />
                <p className="text-xs text-gray-500">Retrieving order details...</p>
              </div>
            ) : (
              <div className="space-y-6 text-xs">
                {/* Meta Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {/* Customer Info */}
                  <div className="p-4 rounded-2xl bg-gray-50 dark:bg-gray-800/40 border border-gray-200/60 dark:border-gray-800 space-y-1.5">
                    <div className="font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-brand-600" /> Customer Information
                    </div>
                    <p className="font-semibold text-gray-800 dark:text-gray-200">{selectedOrder.customer.name}</p>
                    <p className="text-gray-500">{selectedOrder.customer.email}</p>
                    <p className="text-gray-500 font-mono">Phone: {selectedOrder.customer.phone || 'N/A'}</p>
                  </div>

                  {/* Shipping Address */}
                  <div className="p-4 rounded-2xl bg-gray-50 dark:bg-gray-800/40 border border-gray-200/60 dark:border-gray-800 space-y-1.5">
                    <div className="font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-brand-600" /> Shipping Destination
                    </div>
                    {selectedOrder.shipping_address?.full_name ? (
                      <div className="text-gray-600 dark:text-gray-300 space-y-0.5">
                        <p className="font-semibold">{selectedOrder.shipping_address.full_name}</p>
                        <p>{selectedOrder.shipping_address.street_address}</p>
                        <p>{selectedOrder.shipping_address.city}, {selectedOrder.shipping_address.state} {selectedOrder.shipping_address.postal_code}</p>
                      </div>
                    ) : (
                      <p className="text-gray-500">Address recorded on order invoice</p>
                    )}
                  </div>
                </div>

                {/* Items List */}
                <div className="space-y-3">
                  <span className="font-bold text-gray-900 dark:text-white block uppercase tracking-wider text-[11px]">
                    Purchased Line Items ({selectedOrder.items.length})
                  </span>
                  <div className="space-y-2 border border-gray-100 dark:border-gray-800 rounded-2xl p-3">
                    {selectedOrder.items.map((it) => (
                      <div key={it.id} className="flex items-center justify-between gap-3 p-1.5">
                        <div className="flex items-center gap-3">
                          <img
                            src={it.image}
                            alt={it.product_name}
                            className="w-10 h-10 rounded-lg object-cover bg-gray-100 dark:bg-gray-800 shrink-0"
                          />
                          <div>
                            <p className="font-bold text-gray-900 dark:text-white">{it.product_name}</p>
                            <p className="text-[11px] text-gray-500">{it.quantity} × ${it.price.toFixed(2)}</p>
                          </div>
                        </div>
                        <span className="font-black text-gray-900 dark:text-white">
                          ${it.total.toFixed(2)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Status & Financial Breakdown */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-4 border-t border-gray-100 dark:border-gray-800">
                  <div className="flex items-center gap-3">
                    <label className="font-bold text-gray-700 dark:text-gray-300">Update Status:</label>
                    <select
                      value={selectedOrder.status}
                      disabled={isUpdatingStatus}
                      onChange={(e) => handleUpdateStatus(selectedOrder.id, e.target.value)}
                      className="bg-transparent border border-gray-300 dark:border-gray-700 rounded-xl px-3 py-1.5 font-bold text-gray-900 dark:text-white"
                    >
                      <option value="PLACED">PLACED</option>
                      <option value="PROCESSING">PROCESSING</option>
                      <option value="SHIPPED">SHIPPED</option>
                      <option value="DELIVERED">DELIVERED</option>
                      <option value="CANCELLED">CANCELLED (RESTOCK)</option>
                    </select>
                  </div>

                  <div className="text-right space-y-1">
                    <div className="text-gray-500">
                      Subtotal: <span className="font-semibold text-gray-900 dark:text-white">${selectedOrder.subtotal.toFixed(2)}</span>
                    </div>
                    {selectedOrder.discount > 0 && (
                      <div className="text-emerald-600">
                        Discount: -${selectedOrder.discount.toFixed(2)}
                      </div>
                    )}
                    <div className="text-gray-500">
                      Shipping: <span className="font-semibold">{selectedOrder.shipping_fee === 0 ? 'FREE' : `$${selectedOrder.shipping_fee.toFixed(2)}`}</span>
                    </div>
                    <div className="text-base font-black text-gray-900 dark:text-white pt-1 border-t border-gray-200 dark:border-gray-700">
                      Total: ${selectedOrder.total_amount.toFixed(2)}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

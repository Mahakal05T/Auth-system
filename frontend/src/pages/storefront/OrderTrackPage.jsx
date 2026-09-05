import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { orderService } from '../../services/api';
import { 
  CheckCircle2, Circle, ArrowLeft, Truck, Package, 
  MapPin, Clock, CreditCard, ShieldCheck, AlertCircle, Loader2, Ban 
} from 'lucide-react';

export default function OrderTrackPage() {
  const { id } = useParams();
  const [tracking, setTracking] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    setError('');

    orderService.trackOrder(id)
      .then((data) => {
        if (isMounted) setTracking(data);
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.response?.data?.error || 'Could not locate delivery tracking information for this order.');
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => { isMounted = false; };
  }, [id]);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'DELIVERED':
        return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300 border-emerald-200';
      case 'SHIPPED':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/50 dark:text-blue-300 border-blue-200';
      case 'PROCESSING':
      case 'PLACED':
      case 'PENDING':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200';
      case 'CANCELLED':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/50 dark:text-rose-300 border-rose-200';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300 border-gray-200';
    }
  };

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto py-24 text-center space-y-3">
        <Loader2 className="w-8 h-8 text-brand-600 animate-spin mx-auto" />
        <p className="text-xs text-gray-500 font-medium">Tracking order #{id}...</p>
      </div>
    );
  }

  if (error || !tracking) {
    return (
      <div className="max-w-md mx-auto py-16 text-center space-y-4">
        <div className="w-14 h-14 rounded-full bg-rose-50 dark:bg-rose-950/40 text-rose-500 flex items-center justify-center mx-auto">
          <AlertCircle className="w-7 h-7" />
        </div>
        <h2 className="text-lg font-bold text-gray-900 dark:text-white">Unable to Locate Tracking Info</h2>
        <p className="text-xs text-gray-500">{error || 'Order tracking details are not available or access is restricted.'}</p>
        <Link
          to="/orders"
          className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-brand-600 text-white font-bold text-xs"
        >
          <ArrowLeft className="w-4 h-4" /> Return to Orders
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-in fade-in duration-300">
      <div className="flex items-center justify-between">
        <Link
          to="/orders"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-500 hover:text-brand-600 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to My Orders
        </Link>
        <span className="text-[11px] text-gray-400 font-mono">
          Carrier: {tracking.carrier}
        </span>
      </div>

      <div className="p-6 sm:p-8 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-8 shadow-xs">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-gray-100 dark:border-gray-800">
          <div>
            <span className="text-[11px] font-bold text-brand-600 uppercase tracking-wider block">Shipment Status</span>
            <h1 className="text-2xl font-black text-gray-900 dark:text-white font-mono mt-0.5">
              {tracking.order_number}
            </h1>
            <p className="text-xs text-gray-500 mt-1 font-mono">
              Waybill / Tracking No: <strong className="text-gray-700 dark:text-gray-300">{tracking.tracking_number}</strong>
            </p>
          </div>

          <div className="flex flex-col sm:items-end gap-1">
            <span className={`px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider border w-fit ${getStatusBadge(tracking.status)}`}>
              {tracking.status}
            </span>
            <span className="text-[11px] text-gray-500 flex items-center gap-1">
              <Clock className="w-3 h-3 text-brand-600" /> {tracking.estimated_delivery}
            </span>
          </div>
        </div>

        {/* Dynamic Timeline Stepper */}
        <div className="space-y-6">
          <h2 className="text-xs font-bold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
            Delivery Milestones
          </h2>

          <div className="space-y-6 relative pl-6 border-l-2 border-gray-200 dark:border-gray-800 ml-3">
            {tracking.timeline.map((step, idx) => {
              const isCompleted = step.status === 'completed';
              const isCurrent = step.status === 'current';
              const isCancelled = step.status === 'cancelled';

              return (
                <div key={idx} className="relative">
                  <div
                    className={`absolute -left-[31px] top-0.5 w-6 h-6 rounded-full flex items-center justify-center transition-all ${
                      isCompleted
                        ? 'bg-emerald-500 text-white shadow-xs'
                        : isCurrent
                        ? 'bg-brand-600 text-white ring-4 ring-brand-100 dark:ring-brand-950/50 animate-pulse'
                        : isCancelled
                        ? 'bg-rose-500 text-white'
                        : 'bg-gray-200 dark:bg-gray-800 text-gray-400'
                    }`}
                  >
                    {isCompleted ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : isCancelled ? (
                      <Ban className="w-3.5 h-3.5" />
                    ) : (
                      <Circle className="w-2.5 h-2.5 fill-current" />
                    )}
                  </div>

                  <div className="space-y-0.5">
                    <div className="flex items-center justify-between gap-2">
                      <h3
                        className={`text-sm font-bold ${
                          isCompleted || isCurrent
                            ? 'text-gray-900 dark:text-white'
                            : isCancelled
                            ? 'text-rose-600 dark:text-rose-400'
                            : 'text-gray-400'
                        }`}
                      >
                        {step.title}
                      </h3>
                      <span className="text-[11px] text-gray-500 font-mono shrink-0">
                        {step.time}
                      </span>
                    </div>
                    {step.description && (
                      <p className="text-xs text-gray-500">{step.description}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Delivery Address & Summary Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-6 border-t border-gray-100 dark:border-gray-800 text-xs">
          {/* Shipping Address */}
          <div className="p-4 rounded-2xl bg-gray-50 dark:bg-gray-800/40 border border-gray-200/60 dark:border-gray-800 space-y-2">
            <div className="font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
              <MapPin className="w-4 h-4 text-brand-600" /> Delivery Address
            </div>
            {tracking.shipping_address?.full_name ? (
              <div className="text-gray-600 dark:text-gray-300 space-y-0.5 leading-relaxed">
                <p className="font-semibold text-gray-900 dark:text-white">{tracking.shipping_address.full_name}</p>
                <p>{tracking.shipping_address.street_address}</p>
                <p>{tracking.shipping_address.city}, {tracking.shipping_address.state} {tracking.shipping_address.postal_code}</p>
                <p className="text-gray-500 pt-1 font-mono">Phone: {tracking.shipping_address.phone}</p>
              </div>
            ) : (
              <p className="text-gray-500">Address recorded on order invoice</p>
            )}
          </div>

          {/* Payment & Charges */}
          <div className="p-4 rounded-2xl bg-gray-50 dark:bg-gray-800/40 border border-gray-200/60 dark:border-gray-800 space-y-2">
            <div className="font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
              <CreditCard className="w-4 h-4 text-brand-600" /> Payment & Charges
            </div>
            <div className="space-y-1 text-gray-600 dark:text-gray-300">
              <div className="flex justify-between">
                <span>Payment Method</span>
                <span className="font-semibold uppercase text-gray-900 dark:text-white">{tracking.payment_method}</span>
              </div>
              <div className="flex justify-between">
                <span>Payment Status</span>
                <span className="font-semibold text-emerald-600">{tracking.payment_status}</span>
              </div>
              <div className="flex justify-between pt-1 border-t border-gray-200 dark:border-gray-700 font-bold text-gray-900 dark:text-white">
                <span>Total Paid</span>
                <span className="font-black">${tracking.total_amount.toFixed(2)}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Order Items List */}
        {tracking.items && tracking.items.length > 0 && (
          <div className="pt-6 border-t border-gray-100 dark:border-gray-800 space-y-3">
            <h3 className="text-xs font-bold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
              Package Contents ({tracking.items.length} {tracking.items.length === 1 ? 'item' : 'items'})
            </h3>
            <div className="space-y-2.5">
              {tracking.items.map((item) => (
                <div key={item.id} className="flex items-center gap-3 p-2.5 rounded-xl bg-gray-50/50 dark:bg-gray-800/30 text-xs">
                  <img
                    src={item.image}
                    alt={item.product_name}
                    className="w-12 h-12 rounded-lg object-cover bg-gray-100 dark:bg-gray-800 shrink-0"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-gray-900 dark:text-white truncate">{item.product_name}</p>
                    <p className="text-[11px] text-gray-500">Qty: {item.quantity} × ${item.price.toFixed(2)}</p>
                  </div>
                  <span className="font-black text-gray-900 dark:text-white">
                    ${item.total.toFixed(2)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

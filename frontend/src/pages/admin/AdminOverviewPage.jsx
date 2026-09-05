import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  DollarSign, ShoppingBag, Users, Package, TrendingUp, 
  ArrowUpRight, Clock, CheckCircle2, AlertTriangle, ChevronRight, Plus 
} from 'lucide-react';

export default function AdminOverviewPage() {
  const stats = [
    { title: 'Total Sales', value: '$48,290.50', change: '+14.2%', icon: DollarSign, color: 'text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40' },
    { title: 'Total Orders', value: '1,284', change: '+8.4%', icon: ShoppingBag, color: 'text-blue-600 bg-blue-50 dark:bg-blue-950/40' },
    { title: 'Total Customers', value: '892', change: '+12.1%', icon: Users, color: 'text-indigo-600 bg-indigo-50 dark:bg-indigo-950/40' },
    { title: 'Active Products', value: '146', change: '+4 items', icon: Package, color: 'text-purple-600 bg-purple-50 dark:bg-purple-950/40' },
  ];

  const recentOrders = [
    { id: 'ORD-98241', customer: 'Ayush Singh', date: 'Aug 29, 2026', total: '$348.99', status: 'PROCESSING' },
    { id: 'ORD-98240', customer: 'Sarah Connor', date: 'Aug 29, 2026', total: '$189.99', status: 'SHIPPED' },
    { id: 'ORD-98239', customer: 'David Miller', date: 'Aug 28, 2026', total: '$79.50', status: 'DELIVERED' },
    { id: 'ORD-98238', customer: 'Emma Watson', date: 'Aug 28, 2026', total: '$449.99', status: 'DELIVERED' },
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">Admin Operations Center</h1>
          <p className="text-xs text-gray-500 mt-1">E-Commerce store overview, sales performance, and active orders</p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/admin/products"
            className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <Plus className="w-4 h-4" /> Add Product
          </Link>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        {stats.map((stat, idx) => (
          <div
            key={idx}
            className="p-5 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-500">{stat.title}</span>
              <div className={`p-2 rounded-xl ${stat.color}`}>
                <stat.icon className="w-4 h-4" />
              </div>
            </div>
            <div>
              <div className="text-2xl font-black text-gray-900 dark:text-white">{stat.value}</div>
              <div className="text-[11px] text-emerald-600 font-semibold flex items-center gap-1 mt-1">
                <TrendingUp className="w-3.5 h-3.5" />
                <span>{stat.change} vs last month</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Orders Preview */}
      <div className="p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-gray-900 dark:text-white">Recent Customer Orders</h2>
          <Link to="/admin/orders" className="text-xs font-semibold text-brand-600 hover:underline flex items-center gap-1">
            View All Orders <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-100 dark:border-gray-800 text-gray-400 font-semibold">
                <th className="pb-3">Order ID</th>
                <th className="pb-3">Customer</th>
                <th className="pb-3">Date</th>
                <th className="pb-3">Total</th>
                <th className="pb-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {recentOrders.map((ord) => (
                <tr key={ord.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                  <td className="py-3.5 font-mono font-bold text-gray-900 dark:text-white">{ord.id}</td>
                  <td className="py-3.5 text-gray-800 dark:text-gray-200">{ord.customer}</td>
                  <td className="py-3.5 text-gray-500">{ord.date}</td>
                  <td className="py-3.5 font-bold text-gray-900 dark:text-white">{ord.total}</td>
                  <td className="py-3.5">
                    <span className={`px-2.5 py-1 rounded-full font-bold text-[10px] ${
                      ord.status === 'DELIVERED' 
                        ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300'
                        : 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300'
                    }`}>
                      {ord.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

import { useState, useEffect } from 'react';
import { 
  Settings, Store, Truck, Receipt, Package, 
  CreditCard, RotateCcw, Save, Check, AlertCircle, 
  Eye, DollarSign, Percent, Clock, Sparkles, Building2,
  RefreshCw, CheckCircle2
} from 'lucide-react';
import { adminSettingsService } from '../../services/api';
import { toast } from 'react-hot-toast';
import { cn } from '../../utils/helpers';

export default function AdminSettingsPage() {
  const [settings, setSettings] = useState({});
  const [initialSettings, setInitialSettings] = useState({});
  const [activeTab, setActiveTab] = useState('general');
  const [loading, setLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      const res = await adminSettingsService.getSettings();
      if (res.success) {
        setSettings(res.settings || {});
        setInitialSettings(res.settings || {});
      }
    } catch (err) {
      console.error('Failed to load store settings:', err);
      toast.error('Failed to load store configuration');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleChange = (key, value) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleToggle = (key) => {
    setSettings(prev => ({
      ...prev,
      [key]: prev[key] === 'true' ? 'false' : 'true'
    }));
  };

  const hasChanges = JSON.stringify(settings) !== JSON.stringify(initialSettings);

  const handleSave = async (e) => {
    if (e) e.preventDefault();
    try {
      setIsSaving(true);
      const res = await adminSettingsService.updateSettings(settings);
      toast.success(res.message || 'Store settings saved successfully!');
      setInitialSettings(settings);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to update store settings');
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = async () => {
    if (!window.confirm('Are you sure you want to reset all store operational configuration to factory defaults?')) {
      return;
    }
    try {
      setIsResetting(true);
      const res = await adminSettingsService.resetSettings();
      toast.success(res.message);
      fetchSettings();
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to reset settings');
    } finally {
      setIsResetting(false);
    }
  };

  const tabs = [
    { id: 'general', label: 'Store Identity', icon: Store, count: '9 keys' },
    { id: 'shipping', label: 'Shipping & Delivery', icon: Truck, count: '4 keys' },
    { id: 'tax', label: 'Taxes & Rates', icon: Receipt, count: '3 keys' },
    { id: 'inventory', label: 'Inventory Controls', icon: Package, count: '3 keys' },
    { id: 'orders_policies', label: 'Orders & Policies', icon: CreditCard, count: '7 keys' },
  ];

  if (loading && Object.keys(settings).length === 0) {
    return (
      <div className="py-24 text-center space-y-3">
        <RefreshCw className="w-8 h-8 text-brand-600 animate-spin mx-auto" />
        <p className="text-xs text-gray-500">Loading store operational configuration...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-16 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <Settings className="w-7 h-7 text-brand-600 dark:text-brand-400" />
            Store Settings & Operational Configuration
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Configure commercial brand profile, automated shipping calculations, tax compliance, stock thresholds, and checkout policies.
          </p>
        </div>

        {/* Global Save / Reset Action Controls */}
        <div className="flex items-center gap-2.5 self-start sm:self-auto">
          <button
            type="button"
            onClick={handleReset}
            disabled={isResetting || isSaving}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-2xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-xs font-bold text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
          >
            <RotateCcw className={cn("w-3.5 h-3.5", isResetting && "animate-spin")} />
            Reset Defaults
          </button>

          <button
            type="button"
            onClick={handleSave}
            disabled={isSaving || !hasChanges}
            className={cn(
              "inline-flex items-center gap-1.5 px-5 py-2 rounded-2xl text-xs font-bold transition-all shadow-md cursor-pointer",
              hasChanges
                ? "bg-brand-600 hover:bg-brand-700 text-white shadow-brand-600/30 scale-102"
                : "bg-gray-200 dark:bg-gray-800 text-gray-400 cursor-not-allowed"
            )}
          >
            <Save className={cn("w-3.5 h-3.5", isSaving && "animate-spin")} />
            {isSaving ? 'Saving...' : hasChanges ? 'Save Changes' : 'Saved'}
          </button>
        </div>
      </div>

      {/* Unsaved Changes Banner */}
      {hasChanges && (
        <div className="p-3.5 rounded-2xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/50 flex items-center justify-between text-xs text-amber-800 dark:text-amber-300 animate-in slide-in-from-top-2">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-amber-600" />
            <span>You have unsaved operational configuration modifications.</span>
          </div>
          <button
            onClick={handleSave}
            className="font-bold underline hover:text-amber-950 cursor-pointer"
          >
            Save now
          </button>
        </div>
      )}

      {/* Settings Navigation Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-gray-200 dark:border-gray-800">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 rounded-2xl text-xs font-bold whitespace-nowrap transition-all cursor-pointer",
                isActive
                  ? "bg-brand-600 text-white shadow-sm shadow-brand-600/20"
                  : "bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              )}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div className="space-y-6">
        {/* ========================================================= */}
        {/* TAB 1: STORE IDENTITY & GENERAL */}
        {/* ========================================================= */}
        {activeTab === 'general' && (
          <div className="space-y-6 animate-in fade-in">
            {/* Live Announcement Marquee Preview */}
            <div className="p-4 rounded-3xl bg-linear-to-r from-brand-600 to-indigo-700 text-white shadow-md">
              <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider mb-1 opacity-80">
                <span className="flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5" /> Live Announcement Banner Preview
                </span>
                <span>Visible at top of storefront</span>
              </div>
              <p className="text-xs font-medium truncate">
                {settings.announcement_banner || 'Add an announcement banner to display promotions across the storefront.'}
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Brand Profile Card */}
              <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
                <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                  <Store className="w-4 h-4 text-brand-600" />
                  Store Brand Profile
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Store Commercial Name *
                    </label>
                    <input
                      type="text"
                      value={settings.store_name || ''}
                      onChange={(e) => handleChange('store_name', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-bold"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Brand Tagline / Slogan
                    </label>
                    <input
                      type="text"
                      value={settings.store_tagline || ''}
                      onChange={(e) => handleChange('store_tagline', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Storefront Header Announcement Bar
                    </label>
                    <textarea
                      rows={2}
                      value={settings.announcement_banner || ''}
                      onChange={(e) => handleChange('announcement_banner', e.target.value)}
                      placeholder="Promotional discount banner text shown to buyers..."
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>

                  {/* Maintenance Mode Toggle */}
                  <div className="pt-2 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between">
                    <div>
                      <span className="font-bold text-gray-900 dark:text-white block">
                        Store Maintenance Mode
                      </span>
                      <span className="text-[11px] text-gray-400">
                        Displays maintenance screen to shoppers while admin operates
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleToggle('maintenance_mode')}
                      className={cn(
                        "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                        settings.maintenance_mode === 'true' ? "bg-rose-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                          settings.maintenance_mode === 'true' ? "left-6" : "left-1"
                        )}
                      />
                    </button>
                  </div>
                </div>
              </div>

              {/* Contact & Currency Configuration */}
              <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
                <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-brand-600" />
                  Support Contact & Currency
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Customer Support Email
                    </label>
                    <input
                      type="email"
                      value={settings.support_email || ''}
                      onChange={(e) => handleChange('support_email', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Support Helpline Phone
                    </label>
                    <input
                      type="text"
                      value={settings.support_phone || ''}
                      onChange={(e) => handleChange('support_phone', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>

                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Headquarters Physical Address
                    </label>
                    <textarea
                      rows={2}
                      value={settings.store_address || ''}
                      onChange={(e) => handleChange('store_address', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3 pt-2">
                    <div>
                      <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                        Currency Code
                      </label>
                      <select
                        value={settings.currency_code || 'USD'}
                        onChange={(e) => handleChange('currency_code', e.target.value)}
                        className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono"
                      >
                        <option value="USD">USD ($)</option>
                        <option value="EUR">EUR (€)</option>
                        <option value="GBP">GBP (£)</option>
                        <option value="INR">INR (₹)</option>
                        <option value="CAD">CAD ($)</option>
                        <option value="AUD">AUD ($)</option>
                      </select>
                    </div>

                    <div>
                      <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                        Symbol
                      </label>
                      <input
                        type="text"
                        value={settings.currency_symbol || '$'}
                        onChange={(e) => handleChange('currency_symbol', e.target.value)}
                        className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono text-center font-bold"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 2: SHIPPING & FULFILLMENT */}
        {/* ========================================================= */}
        {activeTab === 'shipping' && (
          <div className="space-y-6 animate-in fade-in">
            {/* Free Shipping Dynamic Calculator Preview */}
            <div className="p-4 rounded-3xl bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/50 flex items-center justify-between text-xs text-blue-900 dark:text-blue-200">
              <div className="flex items-center gap-2.5">
                <Truck className="w-5 h-5 text-blue-600" />
                <div>
                  <span className="font-bold block">Complimentary Shipping Trigger</span>
                  <span className="text-blue-600/80 dark:text-blue-400 text-[11px]">
                    Orders exceeding ${parseFloat(settings.free_shipping_threshold || 100).toFixed(2)} automatically get $0 shipping in checkout.
                  </span>
                </div>
              </div>
              <span className="font-mono font-black text-blue-600 text-sm">
                ${parseFloat(settings.free_shipping_threshold || 100).toFixed(2)}
              </span>
            </div>

            <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
              <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                <Truck className="w-4 h-4 text-brand-600" />
                Automated Shipping Calculation Rules
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Standard Shipping Fee ($)
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    value={settings.standard_shipping_fee || '15.00'}
                    onChange={(e) => handleChange('standard_shipping_fee', e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono"
                  />
                  <span className="text-[11px] text-gray-400 mt-0.5 block">
                    Charged when order subtotal is below the free shipping threshold.
                  </span>
                </div>

                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Free Shipping Threshold ($)
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    value={settings.free_shipping_threshold || '100.00'}
                    onChange={(e) => handleChange('free_shipping_threshold', e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono font-bold"
                  />
                  <span className="text-[11px] text-gray-400 mt-0.5 block">
                    Carts meeting or exceeding this subtotal receive free shipping.
                  </span>
                </div>

                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Customer-Facing Transit Time
                  </label>
                  <input
                    type="text"
                    value={settings.estimated_delivery_days || '3-5 business days'}
                    onChange={(e) => handleChange('estimated_delivery_days', e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                  <span className="text-[11px] text-gray-400 mt-0.5 block">
                    Displayed during checkout and in order tracking screen.
                  </span>
                </div>

                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Primary Logistics Carrier Partner
                  </label>
                  <input
                    type="text"
                    value={settings.shipping_carrier_name || 'Apex Express Priority'}
                    onChange={(e) => handleChange('shipping_carrier_name', e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                  <span className="text-[11px] text-gray-400 mt-0.5 block">
                    Carrier label shown in tracking timeline.
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 3: TAXES & COMPLIANCE */}
        {/* ========================================================= */}
        {activeTab === 'tax' && (
          <div className="space-y-6 animate-in fade-in">
            <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
              <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                <Receipt className="w-4 h-4 text-brand-600" />
                Sales Tax & Regional Compliance
              </h3>

              <div className="space-y-4 text-xs">
                {/* Tax Enabled Toggle */}
                <div className="flex items-center justify-between p-3 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800">
                  <div>
                    <span className="font-bold text-gray-900 dark:text-white block">
                      Enable Automated Sales Tax Calculation
                    </span>
                    <span className="text-[11px] text-gray-400">
                      Calculates tax line item during customer checkout
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleToggle('tax_enabled')}
                    className={cn(
                      "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                      settings.tax_enabled === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                    )}
                  >
                    <span
                      className={cn(
                        "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                        settings.tax_enabled === 'true' ? "left-6" : "left-1"
                      )}
                    />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Standard Tax Percentage Rate (%)
                    </label>
                    <div className="relative">
                      <input
                        type="number"
                        step="0.1"
                        value={settings.default_tax_rate || '8.5'}
                        onChange={(e) => handleChange('default_tax_rate', e.target.value)}
                        className="w-full pl-3 pr-8 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono font-bold"
                      />
                      <Percent className="w-4 h-4 text-gray-400 absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                    <span className="text-[11px] text-gray-400 mt-0.5 block">
                      Applied to product subtotal (e.g. 8.5% on $100 = $8.50 tax).
                    </span>
                  </div>

                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Tax Pricing Scheme
                    </label>
                    <select
                      value={settings.tax_included_in_price || 'false'}
                      onChange={(e) => handleChange('tax_included_in_price', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                    >
                      <option value="false">Tax Exclusive (Added at checkout)</option>
                      <option value="true">Tax Inclusive (Included in item price)</option>
                    </select>
                    <span className="text-[11px] text-gray-400 mt-0.5 block">
                      Determines whether catalog prices already include tax.
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 4: INVENTORY & CATALOG */}
        {/* ========================================================= */}
        {activeTab === 'inventory' && (
          <div className="space-y-6 animate-in fade-in">
            <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
              <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                <Package className="w-4 h-4 text-brand-600" />
                Inventory Stock & Catalog Thresholds
              </h3>

              <div className="space-y-4 text-xs">
                <div>
                  <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Low Stock Warning Alert Threshold (Units)
                  </label>
                  <input
                    type="number"
                    value={settings.low_stock_threshold || '5'}
                    onChange={(e) => handleChange('low_stock_threshold', e.target.value)}
                    className="w-full max-w-xs px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono font-bold"
                  />
                  <span className="text-[11px] text-gray-400 mt-0.5 block">
                    Triggers the orange "Only X Left" badge on product pages and highlights in Admin Inventory.
                  </span>
                </div>

                {/* Backorders Toggle */}
                <div className="flex items-center justify-between p-3 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800">
                  <div>
                    <span className="font-bold text-gray-900 dark:text-white block">
                      Allow Product Backorders
                    </span>
                    <span className="text-[11px] text-gray-400">
                      Enables customers to purchase items even when stock level reaches 0
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleToggle('allow_backorders')}
                    className={cn(
                      "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                      settings.allow_backorders === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                    )}
                  >
                    <span
                      className={cn(
                        "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                        settings.allow_backorders === 'true' ? "left-6" : "left-1"
                      )}
                    />
                  </button>
                </div>

                {/* Auto Hide Out of Stock Toggle */}
                <div className="flex items-center justify-between p-3 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800">
                  <div>
                    <span className="font-bold text-gray-900 dark:text-white block">
                      Auto-Hide Out of Stock Products
                    </span>
                    <span className="text-[11px] text-gray-400">
                      Hides product cards from public storefront catalog when inventory is depleted
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleToggle('auto_hide_out_of_stock')}
                    className={cn(
                      "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                      settings.auto_hide_out_of_stock === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                    )}
                  >
                    <span
                      className={cn(
                        "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                        settings.auto_hide_out_of_stock === 'true' ? "left-6" : "left-1"
                      )}
                    />
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 5: ORDERS & CHECKOUT POLICIES */}
        {/* ========================================================= */}
        {activeTab === 'orders_policies' && (
          <div className="space-y-6 animate-in fade-in">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Payment Gateways Toggle Card */}
              <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
                <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                  <CreditCard className="w-4 h-4 text-brand-600" />
                  Active Payment Gateways
                </h3>

                <div className="space-y-3 text-xs">
                  {/* COD */}
                  <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800">
                    <div>
                      <span className="font-bold text-gray-900 dark:text-white block">
                        Cash on Delivery (COD)
                      </span>
                      <span className="text-[11px] text-gray-400">Pay on physical delivery</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleToggle('enable_cod')}
                      className={cn(
                        "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                        settings.enable_cod === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                          settings.enable_cod === 'true' ? "left-6" : "left-1"
                        )}
                      />
                    </button>
                  </div>

                  {/* Cards */}
                  <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800">
                    <div>
                      <span className="font-bold text-gray-900 dark:text-white block">
                        Credit & Debit Cards
                      </span>
                      <span className="text-[11px] text-gray-400">Visa, Mastercard, Amex, Discover</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleToggle('enable_cards')}
                      className={cn(
                        "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                        settings.enable_cards === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                          settings.enable_cards === 'true' ? "left-6" : "left-1"
                        )}
                      />
                    </button>
                  </div>

                  {/* UPI */}
                  <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800">
                    <div>
                      <span className="font-bold text-gray-900 dark:text-white block">
                        UPI & Digital Wallets
                      </span>
                      <span className="text-[11px] text-gray-400">GPay, PhonePe, Paytm, Apple Pay</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleToggle('enable_upi')}
                      className={cn(
                        "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                        settings.enable_upi === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                          settings.enable_upi === 'true' ? "left-6" : "left-1"
                        )}
                      />
                    </button>
                  </div>
                </div>
              </div>

              {/* Order Minimums & Return Policy Card */}
              <div className="p-5 sm:p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4">
                <h3 className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-brand-600" />
                  Order Minimums & Return Window
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Minimum Order Value ($)
                    </label>
                    <input
                      type="number"
                      step="0.01"
                      value={settings.min_order_amount || '10.00'}
                      onChange={(e) => handleChange('min_order_amount', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono"
                    />
                    <span className="text-[11px] text-gray-400 mt-0.5 block">
                      Checkout is disabled if the cart total is lower than this minimum.
                    </span>
                  </div>

                  <div>
                    <label className="block font-bold text-gray-700 dark:text-gray-300 mb-1">
                      Return & Refund Window (Days)
                    </label>
                    <input
                      type="number"
                      value={settings.return_window_days || '30'}
                      onChange={(e) => handleChange('return_window_days', e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 font-mono font-bold"
                    />
                    <span className="text-[11px] text-gray-400 mt-0.5 block">
                      Max days after delivery for customer to submit an RMA return request.
                    </span>
                  </div>

                  {/* Reviews Auto Approval */}
                  <div className="pt-2 border-t border-gray-100 dark:border-gray-800 flex items-center justify-between">
                    <div>
                      <span className="font-bold text-gray-900 dark:text-white block">
                        Auto-Approve Verified Reviews
                      </span>
                      <span className="text-[11px] text-gray-400">
                        Automatically publish customer reviews without holding in queue
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleToggle('auto_approve_reviews')}
                      className={cn(
                        "w-11 h-6 rounded-full transition-colors relative cursor-pointer",
                        settings.auto_approve_reviews === 'true' ? "bg-brand-600" : "bg-gray-300 dark:bg-gray-700"
                      )}
                    >
                      <span
                        className={cn(
                          "w-4 h-4 rounded-full bg-white absolute top-1 transition-transform shadow-xs",
                          settings.auto_approve_reviews === 'true' ? "left-6" : "left-1"
                        )}
                      />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

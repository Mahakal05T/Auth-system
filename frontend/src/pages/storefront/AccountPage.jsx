import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { addressService } from '../../services/api';
import { 
  User, MapPin, KeyRound, LogOut, Save, Plus, 
  Trash2, Edit2, CheckCircle2, Star, Loader2, X 
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function AccountPage() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [name, setName] = useState(user?.name || '');
  const [phone, setPhone] = useState(user?.phone || '');

  // Addresses state
  const [addresses, setAddresses] = useState([]);
  const [isLoadingAddresses, setIsLoadingAddresses] = useState(false);
  const [isAddressModalOpen, setIsAddressModalOpen] = useState(false);
  const [editingAddress, setEditingAddress] = useState(null);

  // Address form fields
  const [formFullName, setFormFullName] = useState('');
  const [formPhone, setFormPhone] = useState('');
  const [formStreet, setFormStreet] = useState('');
  const [formCity, setFormCity] = useState('');
  const [formState, setFormState] = useState('');
  const [formPostalCode, setFormPostalCode] = useState('');
  const [formCountry, setFormCountry] = useState('USA');
  const [formIsDefault, setFormIsDefault] = useState(false);
  const [isSubmittingAddress, setIsSubmittingAddress] = useState(false);

  const fetchAddresses = async () => {
    try {
      setIsLoadingAddresses(true);
      const list = await addressService.getAddresses();
      setAddresses(list);
    } catch (err) {
      console.warn('Could not fetch customer addresses:', err);
    } finally {
      setIsLoadingAddresses(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'addresses') {
      fetchAddresses();
    }
  }, [activeTab]);

  const handleUpdateProfile = (e) => {
    e.preventDefault();
    toast.success('Profile details saved successfully');
  };

  const handleOpenAddModal = () => {
    setEditingAddress(null);
    setFormFullName(user?.name || '');
    setFormPhone(user?.phone || '');
    setFormStreet('');
    setFormCity('');
    setFormState('');
    setFormPostalCode('');
    setFormCountry('USA');
    setFormIsDefault(addresses.length === 0);
    setIsAddressModalOpen(true);
  };

  const handleOpenEditModal = (addr) => {
    setEditingAddress(addr);
    setFormFullName(addr.full_name);
    setFormPhone(addr.phone);
    setFormStreet(addr.street_address);
    setFormCity(addr.city);
    setFormState(addr.state || '');
    setFormPostalCode(addr.postal_code);
    setFormCountry(addr.country || 'USA');
    setFormIsDefault(addr.is_default);
    setIsAddressModalOpen(true);
  };

  const handleSaveAddress = async (e) => {
    e.preventDefault();
    if (!formFullName || !formPhone || !formStreet || !formCity || !formPostalCode) {
      toast.error('Please fill in all required address fields');
      return;
    }

    try {
      setIsSubmittingAddress(true);
      const payload = {
        full_name: formFullName,
        phone: formPhone,
        street_address: formStreet,
        city: formCity,
        state: formState,
        postal_code: formPostalCode,
        country: formCountry,
        is_default: formIsDefault
      };

      if (editingAddress) {
        await addressService.updateAddress(editingAddress.id, payload);
        toast.success('Address updated successfully');
      } else {
        await addressService.addAddress(payload);
        toast.success('Address added successfully');
      }

      setIsAddressModalOpen(false);
      fetchAddresses();
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to save address');
    } finally {
      setIsSubmittingAddress(false);
    }
  };

  const handleDeleteAddress = async (id) => {
    if (!window.confirm('Are you sure you want to delete this delivery address?')) return;
    try {
      await addressService.deleteAddress(id);
      toast.success('Address deleted');
      fetchAddresses();
    } catch (err) {
      toast.error('Failed to delete address');
    }
  };

  const handleSetDefault = async (id) => {
    try {
      await addressService.setDefaultAddress(id);
      toast.success('Default address updated');
      fetchAddresses();
    } catch (err) {
      toast.error('Failed to update default address');
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="pb-4 border-b border-gray-200 dark:border-gray-800">
        <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white">Customer Account</h1>
        <p className="text-xs text-gray-500 mt-1">Manage your personal information, delivery addresses, and account security</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Navigation Tabs */}
        <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-1 h-fit">
          <button
            onClick={() => setActiveTab('profile')}
            className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-semibold transition-colors ${
              activeTab === 'profile'
                ? 'bg-brand-600 text-white shadow-xs'
                : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            <User className="w-4 h-4" /> Personal Profile
          </button>

          <button
            onClick={() => setActiveTab('addresses')}
            className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-semibold transition-colors ${
              activeTab === 'addresses'
                ? 'bg-brand-600 text-white shadow-xs'
                : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            <MapPin className="w-4 h-4" /> Delivery Addresses
          </button>

          <button
            onClick={() => setActiveTab('security')}
            className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-semibold transition-colors ${
              activeTab === 'security'
                ? 'bg-brand-600 text-white shadow-xs'
                : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            <KeyRound className="w-4 h-4" /> Security & Password
          </button>

          <div className="pt-2 border-t border-gray-100 dark:border-gray-800 mt-2">
            <button
              onClick={logout}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-semibold text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition-colors"
            >
              <LogOut className="w-4 h-4" /> Sign Out
            </button>
          </div>
        </div>

        {/* Tab Content Panel */}
        <div className="lg:col-span-3 p-6 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          {activeTab === 'profile' && (
            <form onSubmit={handleUpdateProfile} className="space-y-4 max-w-lg">
              <h2 className="text-base font-bold text-gray-900 dark:text-white">Profile Details</h2>

              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600 dark:text-gray-400">Full Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600 dark:text-gray-400">Email Address (Account ID)</label>
                <input
                  type="email"
                  disabled
                  value={user?.email || ''}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-100 dark:bg-gray-800 text-gray-500 cursor-not-allowed"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600 dark:text-gray-400">Phone Number</label>
                <input
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              <button
                type="submit"
                className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors"
              >
                <Save className="w-4 h-4" /> Save Changes
              </button>
            </form>
          )}

          {activeTab === 'addresses' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-base font-bold text-gray-900 dark:text-white">Delivery Addresses</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Manage shipping addresses for swift one-click checkout</p>
                </div>
                <button
                  onClick={handleOpenAddModal}
                  className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs flex items-center gap-1.5 transition-colors shadow-xs w-fit"
                >
                  <Plus className="w-4 h-4" /> Add New Address
                </button>
              </div>

              {isLoadingAddresses ? (
                <div className="py-12 text-center flex flex-col items-center justify-center space-y-2">
                  <Loader2 className="w-6 h-6 text-brand-600 animate-spin" />
                  <p className="text-xs text-gray-500">Loading saved addresses...</p>
                </div>
              ) : addresses.length === 0 ? (
                <div className="p-8 text-center rounded-2xl border border-dashed border-gray-300 dark:border-gray-700 space-y-3">
                  <MapPin className="w-8 h-8 text-gray-400 mx-auto" />
                  <p className="text-sm font-semibold text-gray-900 dark:text-white">No delivery addresses saved yet</p>
                  <p className="text-xs text-gray-500 max-w-sm mx-auto">
                    Add your home or office address to enable quick checkout and order tracking.
                  </p>
                  <button
                    onClick={handleOpenAddModal}
                    className="mt-2 px-4 py-2 bg-brand-600 text-white rounded-xl text-xs font-semibold"
                  >
                    + Add Address
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {addresses.map((addr) => (
                    <div
                      key={addr.id}
                      className={`p-5 rounded-2xl border flex flex-col justify-between space-y-4 transition-all ${
                        addr.is_default
                          ? 'border-brand-600 bg-brand-50/20 dark:bg-brand-950/20 shadow-xs'
                          : 'border-gray-200 dark:border-gray-800'
                      }`}
                    >
                      <div className="space-y-1.5 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-sm text-gray-900 dark:text-white flex items-center gap-1.5">
                            {addr.full_name}
                          </span>
                          {addr.is_default && (
                            <span className="px-2 py-0.5 rounded-full bg-brand-100 dark:bg-brand-900/50 text-brand-700 dark:text-brand-300 font-extrabold text-[10px]">
                              DEFAULT
                            </span>
                          )}
                        </div>
                        <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                          {addr.street_address}
                        </p>
                        <p className="text-gray-500">
                          {addr.city}, {addr.state} {addr.postal_code}, {addr.country}
                        </p>
                        <p className="text-gray-500 pt-1 font-mono">
                          Phone: {addr.phone}
                        </p>
                      </div>

                      <div className="flex items-center justify-between pt-3 border-t border-gray-100 dark:border-gray-800 text-xs">
                        {!addr.is_default ? (
                          <button
                            onClick={() => handleSetDefault(addr.id)}
                            className="text-brand-600 hover:underline font-semibold"
                          >
                            Set as Default
                          </button>
                        ) : (
                          <span className="text-emerald-600 font-semibold flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Primary
                          </span>
                        )}

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleOpenEditModal(addr)}
                            className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-gray-500 hover:text-brand-600 transition-colors"
                            title="Edit address"
                          >
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleDeleteAddress(addr.id)}
                            className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-gray-400 hover:text-rose-500 transition-colors"
                            title="Delete address"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'security' && (
            <div className="space-y-4 max-w-lg">
              <h2 className="text-base font-bold text-gray-900 dark:text-white">Security Settings</h2>
              <p className="text-xs text-gray-500">Change your password or manage multi-factor verification settings.</p>
              <button
                onClick={() => toast.success('Password update verification sent to your email')}
                className="px-4 py-2 rounded-xl bg-gray-900 text-white dark:bg-white dark:text-gray-900 font-semibold text-xs"
              >
                Update Password
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Add / Edit Address Modal */}
      {isAddressModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800 p-6 sm:p-8 max-w-lg w-full space-y-6 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800">
              <h3 className="font-black text-lg text-gray-900 dark:text-white">
                {editingAddress ? 'Edit Delivery Address' : 'Add New Delivery Address'}
              </h3>
              <button
                onClick={() => setIsAddressModalOpen(false)}
                className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveAddress} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Recipient Full Name *</label>
                  <input
                    type="text"
                    required
                    value={formFullName}
                    onChange={(e) => setFormFullName(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Phone Number *</label>
                  <input
                    type="tel"
                    required
                    value={formPhone}
                    onChange={(e) => setFormPhone(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Street Address *</label>
                <input
                  type="text"
                  required
                  placeholder="Apartment, suite, unit, building, floor, street"
                  value={formStreet}
                  onChange={(e) => setFormStreet(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">City *</label>
                  <input
                    type="text"
                    required
                    value={formCity}
                    onChange={(e) => setFormCity(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">State / Province</label>
                  <input
                    type="text"
                    value={formState}
                    onChange={(e) => setFormState(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1">Postal Code *</label>
                  <input
                    type="text"
                    required
                    value={formPostalCode}
                    onChange={(e) => setFormPostalCode(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="is_default_checkbox"
                  checked={formIsDefault}
                  onChange={(e) => setFormIsDefault(e.target.checked)}
                  className="rounded text-brand-600"
                />
                <label htmlFor="is_default_checkbox" className="text-gray-700 dark:text-gray-300 font-medium cursor-pointer">
                  Set as default delivery address
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-gray-100 dark:border-gray-800">
                <button
                  type="button"
                  onClick={() => setIsAddressModalOpen(false)}
                  className="px-4 py-2.5 rounded-xl border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingAddress}
                  className="px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold transition-colors disabled:opacity-60 shadow-xs"
                >
                  {isSubmittingAddress ? 'Saving...' : 'Save Address'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

import { useState, useEffect, useMemo } from 'react';
import { 
  FolderTree, Folder, Plus, Search, Filter, Check, 
  Edit, Trash2, RefreshCw, X, ChevronDown, ChevronRight, 
  CornerDownRight, Layers, ShoppingBag, CheckCircle2, 
  AlertCircle, ArrowUp, ArrowDown, ExternalLink, Image as ImageIcon,
  Sparkles, Tag
} from 'lucide-react';
import { adminCategoryService } from '../../services/api';
import { toast } from 'react-hot-toast';
import { cn } from '../../utils/helpers';
import { Link } from 'react-router-dom';

const IMAGE_PRESETS = [
  { name: 'Tech & Gadgets', url: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80' },
  { name: 'Fashion & Apparel', url: 'https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=600&q=80' },
  { name: 'Home & Living', url: 'https://images.unsplash.com/photo-1570968915860-54d5c301fa9f?auto=format&fit=crop&w=600&q=80' },
  { name: 'Skincare & Beauty', url: 'https://images.unsplash.com/photo-1620916566398-39f1143ab7be?auto=format&fit=crop&w=600&q=80' },
  { name: 'Fitness & Sports', url: 'https://images.unsplash.com/photo-1517838277536-f5f99be501cd?auto=format&fit=crop&w=600&q=80' },
  { name: 'Books & Media', url: 'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=600&q=80' },
];

export default function AdminCategoriesPage() {
  const [categories, setCategories] = useState([]);
  const [stats, setStats] = useState({
    total_categories: 0,
    active_categories: 0,
    root_categories: 0,
    subcategories: 0,
    total_products_linked: 0,
    uncategorized_products: 0,
  });
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [levelFilter, setLevelFilter] = useState('all');

  // Expanded root category row state for tree view
  const [collapsedParents, setCollapsedParents] = useState(new Set());

  // Create / Edit modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingCategory, setEditingCategory] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Delete modal state
  const [deletingCategory, setDeletingCategory] = useState(null);
  const [reassignTargetId, setReassignTargetId] = useState('');
  const [hardDeleteConfirm, setHardDeleteConfirm] = useState(false);

  // Form State
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    parent_id: '',
    description: '',
    image_url: '',
    display_order: 0,
    is_active: true,
  });

  const fetchCategories = async () => {
    try {
      setLoading(true);
      const params = {};
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (statusFilter !== 'all') params.status = statusFilter;
      if (levelFilter !== 'all') params.level = levelFilter;

      const res = await adminCategoryService.getCategories(params);
      if (res.success) {
        setCategories(res.categories || []);
        if (res.stats) setStats(res.stats);
      }
    } catch (err) {
      console.error('Error fetching categories:', err);
      toast.error('Failed to load categories');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchCategories();
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery, statusFilter, levelFilter]);

  // Organize categories into hierarchy
  const { rootCategories, subcategoriesByParent, allRoots } = useMemo(() => {
    const roots = [];
    const subsMap = {};
    const rootsList = [];

    // First scan all roots for parent selectors
    categories.forEach(c => {
      if (!c.parent_id) {
        rootsList.push(c);
      }
    });

    categories.forEach(c => {
      if (!c.parent_id) {
        roots.push(c);
      } else {
        if (!subsMap[c.parent_id]) subsMap[c.parent_id] = [];
        subsMap[c.parent_id].push(c);
      }
    });

    return { rootCategories: roots, subcategoriesByParent: subsMap, allRoots: rootsList };
  }, [categories]);

  const toggleCollapse = (parentId) => {
    setCollapsedParents(prev => {
      const next = new Set(prev);
      if (next.has(parentId)) {
        next.delete(parentId);
      } else {
        next.add(parentId);
      }
      return next;
    });
  };

  const handleOpenCreateModal = (presetParentId = '') => {
    setEditingCategory(null);
    setFormData({
      name: '',
      slug: '',
      parent_id: presetParentId ? String(presetParentId) : '',
      description: '',
      image_url: '',
      display_order: categories.length + 1,
      is_active: true,
    });
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (cat) => {
    setEditingCategory(cat);
    setFormData({
      name: cat.name,
      slug: cat.slug || '',
      parent_id: cat.parent_id ? String(cat.parent_id) : '',
      description: cat.description || '',
      image_url: cat.image_url || '',
      display_order: cat.display_order ?? 0,
      is_active: Boolean(cat.is_active),
    });
    setIsModalOpen(true);
  };

  const handleNameChange = (e) => {
    const name = e.target.value;
    const generatedSlug = name
      .toLowerCase()
      .trim()
      .replace(/[^\w\s-]/g, '')
      .replace(/[\s_-]+/g, '-');

    setFormData(prev => ({
      ...prev,
      name,
      slug: editingCategory ? prev.slug : generatedSlug
    }));
  };

  const handleSaveCategory = async (e) => {
    e.preventDefault();
    const name = formData.name.trim();
    if (!name) {
      toast.error('Category name is required');
      return;
    }

    const payload = {
      name,
      slug: formData.slug.trim(),
      parent_id: formData.parent_id ? parseInt(formData.parent_id, 10) : null,
      description: formData.description.trim(),
      image_url: formData.image_url.trim(),
      display_order: parseInt(formData.display_order, 10) || 0,
      is_active: formData.is_active,
    };

    try {
      setIsSubmitting(true);
      if (editingCategory) {
        const res = await adminCategoryService.updateCategory(editingCategory.id, payload);
        toast.success(res.message || 'Category updated');
      } else {
        const res = await adminCategoryService.createCategory(payload);
        toast.success(res.message || 'Category created');
      }
      setIsModalOpen(false);
      fetchCategories();
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to save category';
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleStatus = async (cat) => {
    try {
      const res = await adminCategoryService.toggleCategoryStatus(cat.id);
      toast.success(res.message);
      setCategories(prev => prev.map(c => c.id === cat.id ? { ...c, is_active: res.is_active } : c));
      setStats(prev => ({
        ...prev,
        active_categories: res.is_active ? prev.active_categories + 1 : Math.max(0, prev.active_categories - 1)
      }));
    } catch (err) {
      toast.error('Failed to update status');
    }
  };

  const handleMoveOrder = async (cat, direction) => {
    const currentOrder = cat.display_order || 0;
    const newOrder = direction === 'up' ? Math.max(0, currentOrder - 1) : currentOrder + 1;
    
    try {
      await adminCategoryService.updateCategory(cat.id, { display_order: newOrder });
      toast.success(`Moved ${cat.name} ${direction}`);
      fetchCategories();
    } catch (err) {
      toast.error('Failed to change order');
    }
  };

  const handleDeleteCategory = async () => {
    if (!deletingCategory) return;
    try {
      const params = {
        hard_delete: hardDeleteConfirm,
      };
      if (reassignTargetId) {
        params.reassign_to = parseInt(reassignTargetId, 10);
      }

      const res = await adminCategoryService.deleteCategory(deletingCategory.id, params);
      toast.success(res.message);
      setDeletingCategory(null);
      fetchCategories();
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to delete category';
      toast.error(msg);
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <FolderTree className="w-7 h-7 text-brand-600 dark:text-brand-400" />
            Category Taxonomy & Hierarchy
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Build multi-tier storefront category trees, adjust visual order, assign lifestyle photography, and manage product linkages.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleOpenCreateModal('')}
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-brand-600 hover:bg-brand-700 text-white text-xs font-bold rounded-2xl shadow-md shadow-brand-600/20 transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            Add Root Category
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 sm:gap-4">
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Taxonomy</span>
            <div className="w-8 h-8 rounded-xl bg-blue-50 dark:bg-blue-950/40 text-blue-600 flex items-center justify-center">
              <FolderTree className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.total_categories}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Total defined categories</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Active Online</span>
            <div className="w-8 h-8 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 flex items-center justify-center">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-emerald-600 mt-2">
            {stats.active_categories}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Visible to storefront</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Root Categories</span>
            <div className="w-8 h-8 rounded-xl bg-purple-50 dark:bg-purple-950/40 text-purple-600 flex items-center justify-center">
              <Folder className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.root_categories}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Primary departments</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Subcategories</span>
            <div className="w-8 h-8 rounded-xl bg-amber-50 dark:bg-amber-950/40 text-amber-600 flex items-center justify-center">
              <CornerDownRight className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.subcategories}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Nested tiers</span>
        </div>

        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Catalog Products</span>
            <div className="w-8 h-8 rounded-xl bg-rose-50 dark:bg-rose-950/40 text-rose-600 flex items-center justify-center">
              <ShoppingBag className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.total_products_linked}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Mapped to categories</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search category, slug, or details..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          {/* Level Filter */}
          <div className="flex bg-gray-100 dark:bg-gray-800 p-1 rounded-2xl text-xs font-medium text-gray-600 dark:text-gray-300">
            {[
              { id: 'all', label: 'All Tiers' },
              { id: 'root', label: 'Roots Only' },
              { id: 'sub', label: 'Subcategories' },
            ].map((lvl) => (
              <button
                key={lvl.id}
                onClick={() => setLevelFilter(lvl.id)}
                className={cn(
                  "px-3 py-1.5 rounded-xl transition-all whitespace-nowrap",
                  levelFilter === lvl.id 
                    ? "bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-bold shadow-xs" 
                    : "hover:text-gray-900 dark:hover:text-white"
                )}
              >
                {lvl.label}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-200 focus:outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active Online</option>
            <option value="inactive">Inactive / Hidden</option>
          </select>

          <button
            onClick={fetchCategories}
            className="p-2 rounded-xl text-gray-500 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            title="Refresh categories"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Categories Hierarchy Table */}
      <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800 overflow-hidden shadow-xs">
        {loading && categories.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-xs">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-brand-600" />
            Loading category hierarchy...
          </div>
        ) : categories.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <FolderTree className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-700" />
            <h3 className="text-sm font-bold text-gray-900 dark:text-white">No categories found</h3>
            <p className="text-xs text-gray-500 max-w-sm mx-auto">
              Create your first department or category to organize products across the storefront navigation.
            </p>
            <button
              onClick={() => handleOpenCreateModal('')}
              className="px-4 py-2 bg-brand-600 text-white rounded-xl text-xs font-bold hover:bg-brand-700 inline-flex items-center gap-1.5"
            >
              <Plus className="w-4 h-4" /> Add Root Category
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 dark:bg-gray-950/50 text-gray-500 border-b border-gray-200 dark:border-gray-800 uppercase tracking-wider text-[10px] font-bold">
                <tr>
                  <th className="py-3.5 px-4">Category Name & Tier</th>
                  <th className="py-3.5 px-4">URL Slug</th>
                  <th className="py-3.5 px-4">Subcategories</th>
                  <th className="py-3.5 px-4">Catalog Products</th>
                  <th className="py-3.5 px-4 text-center">Order</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800/60 font-normal">
                {rootCategories.map((root) => {
                  const children = subcategoriesByParent[root.id] || [];
                  const isCollapsed = collapsedParents.has(root.id);

                  return (
                    <div key={`group-${root.id}`} style={{ display: 'contents' }}>
                      {/* Root Category Row */}
                      <tr className="hover:bg-gray-50/70 dark:hover:bg-gray-800/30 transition-colors bg-white dark:bg-gray-900">
                        {/* Name and Thumbnail */}
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-3">
                            {/* Expand / Collapse Button */}
                            {children.length > 0 ? (
                              <button
                                onClick={() => toggleCollapse(root.id)}
                                className="p-1 rounded text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                                title={isCollapsed ? "Expand subcategories" : "Collapse subcategories"}
                              >
                                {isCollapsed ? (
                                  <ChevronRight className="w-4 h-4" />
                                ) : (
                                  <ChevronDown className="w-4 h-4 text-brand-600" />
                                )}
                              </button>
                            ) : (
                              <div className="w-6 h-6 flex items-center justify-center text-gray-300">
                                •
                              </div>
                            )}

                            {/* Thumbnail */}
                            <div className="w-10 h-10 rounded-xl overflow-hidden bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shrink-0">
                              {root.image_url ? (
                                <img
                                  src={root.image_url}
                                  alt={root.name}
                                  className="w-full h-full object-cover"
                                  onError={(e) => { e.target.src = 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=100&q=80'; }}
                                />
                              ) : (
                                <div className="w-full h-full flex items-center justify-center font-black text-gray-400 text-xs">
                                  {root.name[0]}
                                </div>
                              )}
                            </div>

                            <div>
                              <div className="font-black text-sm text-gray-900 dark:text-white flex items-center gap-2">
                                <span>{root.name}</span>
                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-md bg-purple-50 dark:bg-purple-950/50 text-purple-600 dark:text-purple-400 border border-purple-200 dark:border-purple-800">
                                  ROOT
                                </span>
                              </div>
                              <p className="text-[11px] text-gray-500 truncate max-w-xs mt-0.5">
                                {root.description || 'No description provided'}
                              </p>
                            </div>
                          </div>
                        </td>

                        {/* Slug */}
                        <td className="py-3.5 px-4 font-mono text-[11px] text-gray-500">
                          <span className="px-2 py-1 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                            /{root.slug}
                          </span>
                        </td>

                        {/* Subcategories count */}
                        <td className="py-3.5 px-4">
                          <span className={cn(
                            "inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold",
                            children.length > 0 
                              ? "bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300"
                              : "bg-gray-100 dark:bg-gray-800 text-gray-400"
                          )}>
                            <CornerDownRight className="w-3 h-3" />
                            {children.length} {children.length === 1 ? 'sub' : 'subs'}
                          </span>
                        </td>

                        {/* Products */}
                        <td className="py-3.5 px-4">
                          <Link
                            to={`/admin/products?category=${root.slug}`}
                            className="inline-flex items-center gap-1.5 text-xs font-bold text-gray-700 dark:text-gray-300 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                          >
                            <ShoppingBag className="w-3.5 h-3.5 text-gray-400" />
                            <span>{root.product_count} products</span>
                          </Link>
                        </td>

                        {/* Display Order */}
                        <td className="py-3.5 px-4 text-center">
                          <div className="inline-flex items-center gap-1 bg-gray-50 dark:bg-gray-800 px-2 py-1 rounded-lg border border-gray-200 dark:border-gray-700">
                            <span className="font-bold text-xs">{root.display_order ?? 0}</span>
                            <div className="flex flex-col">
                              <button
                                onClick={() => handleMoveOrder(root, 'up')}
                                className="p-0.5 text-gray-400 hover:text-brand-600"
                                title="Move Up"
                              >
                                <ArrowUp className="w-2.5 h-2.5" />
                              </button>
                              <button
                                onClick={() => handleMoveOrder(root, 'down')}
                                className="p-0.5 text-gray-400 hover:text-brand-600"
                                title="Move Down"
                              >
                                <ArrowDown className="w-2.5 h-2.5" />
                              </button>
                            </div>
                          </div>
                        </td>

                        {/* Status */}
                        <td className="py-3.5 px-4">
                          <button
                            onClick={() => handleToggleStatus(root)}
                            className={cn(
                              "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-bold text-[10px] transition-all cursor-pointer",
                              root.is_active 
                                ? "bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-200" 
                                : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200"
                            )}
                            title="Click to toggle status"
                          >
                            <span className={cn(
                              "w-1.5 h-1.5 rounded-full",
                              root.is_active ? "bg-emerald-500" : "bg-gray-400"
                            )} />
                            {root.is_active ? 'ACTIVE' : 'HIDDEN'}
                          </button>
                        </td>

                        {/* Actions */}
                        <td className="py-3.5 px-4 text-right">
                          <div className="inline-flex items-center gap-1">
                            <button
                              onClick={() => handleOpenCreateModal(root.id)}
                              className="p-1.5 text-gray-400 hover:text-purple-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                              title="Add subcategory"
                            >
                              <Plus className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleOpenEditModal(root)}
                              className="p-1.5 text-gray-400 hover:text-blue-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                              title="Edit category"
                            >
                              <Edit className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => {
                                setDeletingCategory(root);
                                setReassignTargetId('');
                                setHardDeleteConfirm(false);
                              }}
                              className="p-1.5 text-gray-400 hover:text-rose-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                              title="Delete category"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Indented Subcategories Rows */}
                      {!isCollapsed && children.map((sub) => (
                        <tr 
                          key={`sub-${sub.id}`} 
                          className="hover:bg-gray-50/50 dark:hover:bg-gray-800/20 transition-colors bg-gray-50/30 dark:bg-gray-950/20"
                        >
                          <td className="py-3 px-4 pl-12">
                            <div className="flex items-center gap-3">
                              {/* Tree connector line icon */}
                              <div className="text-gray-400 flex items-center gap-1">
                                <CornerDownRight className="w-4 h-4 text-brand-500 shrink-0" />
                              </div>

                              {/* Thumbnail */}
                              <div className="w-8 h-8 rounded-lg overflow-hidden bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shrink-0">
                                {sub.image_url ? (
                                  <img
                                    src={sub.image_url}
                                    alt={sub.name}
                                    className="w-full h-full object-cover"
                                  />
                                ) : (
                                  <div className="w-full h-full flex items-center justify-center font-black text-gray-400 text-[10px]">
                                    {sub.name[0]}
                                  </div>
                                )}
                              </div>

                              <div>
                                <div className="font-bold text-xs text-gray-900 dark:text-white flex items-center gap-2">
                                  <span>{sub.name}</span>
                                  <span className="text-[9px] font-medium text-gray-400">
                                    in {root.name}
                                  </span>
                                </div>
                                <p className="text-[10px] text-gray-400 truncate max-w-xs">
                                  {sub.description || 'Subcategory'}
                                </p>
                              </div>
                            </div>
                          </td>

                          {/* Sub Slug */}
                          <td className="py-3 px-4 font-mono text-[10px] text-gray-500">
                            <span className="px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">
                              /{sub.slug}
                            </span>
                          </td>

                          {/* Sub Tier */}
                          <td className="py-3 px-4 text-[11px] text-gray-400 italic">
                            Tier 2 Child
                          </td>

                          {/* Products */}
                          <td className="py-3 px-4">
                            <Link
                              to={`/admin/products?category=${sub.slug}`}
                              className="inline-flex items-center gap-1 text-xs text-gray-600 dark:text-gray-400 hover:text-brand-600 transition-colors"
                            >
                              <ShoppingBag className="w-3 h-3 text-gray-400" />
                              <span>{sub.product_count} products</span>
                            </Link>
                          </td>

                          {/* Display Order */}
                          <td className="py-3 px-4 text-center">
                            <div className="inline-flex items-center gap-1 bg-white dark:bg-gray-900 px-1.5 py-0.5 rounded border border-gray-200 dark:border-gray-700 text-[11px]">
                              <span>{sub.display_order ?? 0}</span>
                              <div className="flex flex-col">
                                <button
                                  onClick={() => handleMoveOrder(sub, 'up')}
                                  className="p-0.5 text-gray-400 hover:text-brand-600"
                                >
                                  <ArrowUp className="w-2 h-2" />
                                </button>
                                <button
                                  onClick={() => handleMoveOrder(sub, 'down')}
                                  className="p-0.5 text-gray-400 hover:text-brand-600"
                                >
                                  <ArrowDown className="w-2 h-2" />
                                </button>
                              </div>
                            </div>
                          </td>

                          {/* Status */}
                          <td className="py-3 px-4">
                            <button
                              onClick={() => handleToggleStatus(sub)}
                              className={cn(
                                "inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-bold text-[9px] transition-all cursor-pointer",
                                sub.is_active 
                                  ? "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400" 
                                  : "bg-gray-100 dark:bg-gray-800 text-gray-400"
                              )}
                            >
                              <span className={cn(
                                "w-1 h-1 rounded-full",
                                sub.is_active ? "bg-emerald-500" : "bg-gray-400"
                              )} />
                              {sub.is_active ? 'ACTIVE' : 'HIDDEN'}
                            </button>
                          </td>

                          {/* Actions */}
                          <td className="py-3 px-4 text-right">
                            <div className="inline-flex items-center gap-1">
                              <button
                                onClick={() => handleOpenEditModal(sub)}
                                className="p-1 text-gray-400 hover:text-blue-600 rounded hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                                title="Edit subcategory"
                              >
                                <Edit className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => {
                                  setDeletingCategory(sub);
                                  setReassignTargetId('');
                                  setHardDeleteConfirm(false);
                                }}
                                className="p-1 text-gray-400 hover:text-rose-600 rounded hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                                title="Delete subcategory"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </div>
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
                <FolderTree className="w-5 h-5 text-brand-600" />
                <h3 className="font-black text-sm text-gray-900 dark:text-white">
                  {editingCategory ? `Edit Category: ${editingCategory.name}` : 'Create New Category'}
                </h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveCategory} className="p-6 space-y-4 overflow-y-auto flex-1">
              {/* Category Name & Slug */}
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    Category Name *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Wireless Audio"
                    value={formData.name}
                    onChange={handleNameChange}
                    className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                    URL Slug
                  </label>
                  <div className="flex items-center rounded-xl border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-950 px-3 py-1.5">
                    <span className="text-xs text-gray-400 font-mono">/category/</span>
                    <input
                      type="text"
                      required
                      placeholder="wireless-audio"
                      value={formData.slug}
                      onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
                      className="flex-1 text-xs font-mono bg-transparent text-gray-900 dark:text-white focus:outline-none pl-1"
                    />
                  </div>
                </div>
              </div>

              {/* Hierarchy Tier Parent Selector */}
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Parent Hierarchy Tier
                </label>
                <select
                  value={formData.parent_id}
                  onChange={(e) => setFormData({ ...formData, parent_id: e.target.value })}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                >
                  <option value="">None (Top-Level Root Department)</option>
                  {allRoots.map((parent) => (
                    <option
                      key={parent.id}
                      value={parent.id}
                      disabled={editingCategory && parent.id === editingCategory.id}
                    >
                      Under: {parent.name}
                    </option>
                  ))}
                </select>
                <p className="text-[10px] text-gray-400 mt-1">
                  Select a root department to make this a nested subcategory, or leave blank as a top-level category.
                </p>
              </div>

              {/* Display Order */}
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Display Order Sorting Index
                </label>
                <input
                  type="number"
                  value={formData.display_order}
                  onChange={(e) => setFormData({ ...formData, display_order: e.target.value })}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
                <span className="text-[10px] text-gray-400 mt-1 block">
                  Lower numbers display earlier in navigation menus.
                </span>
              </div>

              {/* Cover Image & Presets */}
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Cover Image URL
                </label>
                <div className="flex gap-2">
                  <input
                    type="url"
                    placeholder="https://images.unsplash.com/photo-..."
                    value={formData.image_url}
                    onChange={(e) => setFormData({ ...formData, image_url: e.target.value })}
                    className="flex-1 px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                  />
                  {formData.image_url && (
                    <div className="w-10 h-10 rounded-xl overflow-hidden border border-gray-300 dark:border-gray-700 shrink-0 bg-gray-100">
                      <img src={formData.image_url} alt="Preview" className="w-full h-full object-cover" />
                    </div>
                  )}
                </div>

                {/* Preset Suggestions */}
                <div className="mt-2">
                  <span className="text-[10px] font-bold text-gray-400 flex items-center gap-1 mb-1">
                    <Sparkles className="w-3 h-3 text-amber-500" /> Or pick a curated preset:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {IMAGE_PRESETS.map((p) => (
                      <button
                        key={p.name}
                        type="button"
                        onClick={() => setFormData({ ...formData, image_url: p.url })}
                        className="px-2 py-1 text-[10px] rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-brand-50 hover:text-brand-600 transition-colors"
                      >
                        {p.name}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Description / Marketing Headline
                </label>
                <textarea
                  rows={2}
                  placeholder="Summarize the products curated under this category..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              {/* Active Toggle */}
              <label className="flex items-center gap-2 pt-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.is_active}
                  onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                  className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                />
                <span className="text-xs font-bold text-gray-800 dark:text-gray-200">
                  Visible & active on storefront navigation
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
                  {isSubmitting ? 'Saving...' : (editingCategory ? 'Update Category' : 'Create Category')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete / Reassign Modal */}
      {deletingCategory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl w-full max-w-md shadow-2xl overflow-hidden p-6 space-y-4">
            <div className="flex items-center gap-2 text-rose-600">
              <AlertCircle className="w-5 h-5" />
              <h3 className="font-black text-sm text-gray-900 dark:text-white">
                Delete Category "{deletingCategory.name}"?
              </h3>
            </div>

            <p className="text-xs text-gray-500">
              This category currently has{' '}
              <strong className="text-gray-900 dark:text-white">{deletingCategory.product_count} products</strong>{' '}
              and{' '}
              <strong className="text-gray-900 dark:text-white">{deletingCategory.subcategory_count} subcategories</strong>.
            </p>

            {deletingCategory.product_count > 0 && (
              <div className="space-y-2 pt-1">
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300">
                  Reassign existing products to:
                </label>
                <select
                  value={reassignTargetId}
                  onChange={(e) => setReassignTargetId(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none"
                >
                  <option value="">Leave Uncategorized (NULL)</option>
                  {categories
                    .filter(c => c.id !== deletingCategory.id)
                    .map(c => (
                      <option key={c.id} value={c.id}>
                        {c.name} {c.parent_name ? `(${c.parent_name})` : ''}
                      </option>
                    ))}
                </select>
              </div>
            )}

            <label className="flex items-center gap-2 pt-2 cursor-pointer">
              <input
                type="checkbox"
                checked={hardDeleteConfirm}
                onChange={(e) => setHardDeleteConfirm(e.target.checked)}
                className="rounded border-gray-300 text-rose-600 focus:ring-rose-500"
              />
              <span className="text-xs text-gray-700 dark:text-gray-300 font-medium">
                Permanently purge from database (otherwise soft-deactivates)
              </span>
            </label>

            <div className="pt-3 border-t border-gray-200 dark:border-gray-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeletingCategory(null)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteCategory}
                className="px-5 py-2 rounded-xl text-xs font-bold bg-rose-600 hover:bg-rose-700 text-white shadow-md shadow-rose-600/20"
              >
                {hardDeleteConfirm ? 'Permanently Delete' : 'Deactivate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

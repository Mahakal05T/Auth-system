import { useState, useEffect } from 'react';
import { 
  Star, MessageSquare, CheckCircle2, AlertTriangle, 
  Eye, EyeOff, Trash2, Search, Filter, RefreshCw, 
  ExternalLink, CornerDownRight, BadgeCheck, Send, 
  Edit3, Clock, Sparkles, X, ChevronLeft, ChevronRight
} from 'lucide-react';
import { adminReviewService } from '../../services/api';
import { toast } from 'react-hot-toast';
import { cn } from '../../utils/helpers';
import { Link } from 'react-router-dom';

const QUICK_REPLIES = [
  "Thank you for sharing your experience! We're thrilled you love your purchase.",
  "Thanks for the great feedback! Quality and customer satisfaction are our top priorities.",
  "We appreciate your honest review. If you ever need assistance, our support team is always here to help.",
  "Thank you for your review. We are continuously improving our products based on customer feedback."
];

export default function AdminReviewsPage() {
  const [reviews, setReviews] = useState([]);
  const [stats, setStats] = useState({
    total_reviews: 0,
    approved_reviews: 0,
    pending_reviews: 0,
    hidden_reviews: 0,
    verified_reviews: 0,
    average_rating: 5.0,
    rating_distribution: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
  });
  const [loading, setLoading] = useState(true);

  // Filters & pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [ratingFilter, setRatingFilter] = useState('all');
  const [verifiedFilter, setVerifiedFilter] = useState('all');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);

  // Reply modal state
  const [replyingReview, setReplyingReview] = useState(null);
  const [replyText, setReplyText] = useState('');
  const [isSubmittingReply, setIsSubmittingReply] = useState(false);

  const fetchReviews = async (currPage = page) => {
    try {
      setLoading(true);
      const params = {
        page: currPage,
        limit: 10
      };
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (statusFilter !== 'all') params.status = statusFilter;
      if (ratingFilter !== 'all') params.rating = ratingFilter;
      if (verifiedFilter !== 'all') params.verified = verifiedFilter;

      const res = await adminReviewService.getReviews(params);
      if (res.success) {
        setReviews(res.reviews || []);
        if (res.stats) setStats(res.stats);
        setPage(res.page || 1);
        setTotalPages(res.total_pages || 1);
        setTotalItems(res.total || 0);
      }
    } catch (err) {
      console.error('Error fetching reviews:', err);
      toast.error('Failed to load reviews');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchReviews(1);
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery, statusFilter, ratingFilter, verifiedFilter]);

  const handleUpdateStatus = async (reviewId, newStatus) => {
    try {
      const res = await adminReviewService.updateStatus(reviewId, newStatus);
      toast.success(res.message);
      setReviews(prev => prev.map(r => r.id === reviewId ? { ...r, status: newStatus } : r));
      // Re-fetch stats in background
      adminReviewService.getReviews({ limit: 1 }).then(r => {
        if (r.stats) setStats(r.stats);
      });
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to update status');
    }
  };

  const handleDeleteReview = async (review) => {
    if (!window.confirm(`Are you sure you want to permanently delete review #${review.id}?`)) return;

    try {
      const res = await adminReviewService.deleteReview(review.id);
      toast.success(res.message);
      fetchReviews(page);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to delete review');
    }
  };

  const handleOpenReplyModal = (review) => {
    setReplyingReview(review);
    setReplyText(review.admin_reply || '');
  };

  const handleSaveReply = async (e) => {
    e.preventDefault();
    if (!replyText.trim()) {
      toast.error('Reply text cannot be empty');
      return;
    }

    try {
      setIsSubmittingReply(true);
      const res = await adminReviewService.postReply(replyingReview.id, replyText.trim());
      toast.success(res.message);
      setReviews(prev => prev.map(r => r.id === replyingReview.id ? { 
        ...r, 
        admin_reply: res.admin_reply,
        admin_reply_at: res.admin_reply_at
      } : r));
      setReplyingReview(null);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to post reply');
    } finally {
      setIsSubmittingReply(false);
    }
  };

  const handleDeleteReply = async (reviewId) => {
    if (!window.confirm('Remove official response?')) return;
    try {
      const res = await adminReviewService.deleteReply(reviewId);
      toast.success(res.message);
      setReviews(prev => prev.map(r => r.id === reviewId ? { 
        ...r, 
        admin_reply: null, 
        admin_reply_at: null 
      } : r));
    } catch (err) {
      toast.error('Failed to remove reply');
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-gray-900 dark:text-white flex items-center gap-2.5">
            <Star className="w-7 h-7 text-amber-500 fill-amber-500" />
            Customer Reviews & Ratings Moderation
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Analyze customer satisfaction scores, respond officially to user feedback, and moderate public catalog ratings.
          </p>
        </div>

        <button
          onClick={() => fetchReviews(page)}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-xs font-bold rounded-2xl shadow-xs text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors self-start sm:self-auto cursor-pointer"
        >
          <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
          Refresh Feed
        </button>
      </div>

      {/* KPI Stats Overview */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 sm:gap-4">
        {/* Average Rating Card */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Store Average</span>
            <div className="w-8 h-8 rounded-xl bg-amber-50 dark:bg-amber-950/40 text-amber-500 flex items-center justify-center">
              <Star className="w-4 h-4 fill-amber-500" />
            </div>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-gray-900 dark:text-white">
              {stats.average_rating}
            </span>
            <span className="text-xs text-gray-400">/ 5.0</span>
          </div>
          <div className="flex items-center gap-1 text-amber-400 mt-1">
            {[1, 2, 3, 4, 5].map((s) => (
              <Star
                key={s}
                className={cn(
                  "w-3 h-3",
                  s <= Math.round(stats.average_rating) ? "fill-amber-400 text-amber-400" : "text-gray-300 dark:text-gray-700"
                )}
              />
            ))}
          </div>
        </div>

        {/* Total Reviews */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Total Reviews</span>
            <div className="w-8 h-8 rounded-xl bg-blue-50 dark:bg-blue-950/40 text-blue-600 flex items-center justify-center">
              <MessageSquare className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-gray-900 dark:text-white mt-2">
            {stats.total_reviews}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">
            {stats.verified_reviews} verified buyers
          </span>
        </div>

        {/* Approved Online */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Live & Approved</span>
            <div className="w-8 h-8 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 flex items-center justify-center">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-emerald-600 mt-2">
            {stats.approved_reviews}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Published on site</span>
        </div>

        {/* Pending Moderation */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Pending Approval</span>
            <div className="w-8 h-8 rounded-xl bg-purple-50 dark:bg-purple-950/40 text-purple-600 flex items-center justify-center">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-purple-600 mt-2">
            {stats.pending_reviews}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Review queue</span>
        </div>

        {/* Hidden / Flagged */}
        <div className="p-4 sm:p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-500">Hidden / Flagged</span>
            <div className="w-8 h-8 rounded-xl bg-rose-50 dark:bg-rose-950/40 text-rose-600 flex items-center justify-center">
              <EyeOff className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-rose-600 mt-2">
            {stats.hidden_reviews}
          </div>
          <span className="text-[11px] text-gray-400 mt-0.5 block">Filtered out</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search reviewer, product, or comment..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          {/* Status Tabs */}
          <div className="flex bg-gray-100 dark:bg-gray-800 p-1 rounded-2xl text-xs font-medium text-gray-600 dark:text-gray-300">
            {['all', 'approved', 'pending', 'hidden'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={cn(
                  "px-3 py-1.5 rounded-xl capitalize transition-all whitespace-nowrap",
                  statusFilter === st 
                    ? "bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-bold shadow-xs" 
                    : "hover:text-gray-900 dark:hover:text-white"
                )}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Star Filter */}
          <select
            value={ratingFilter}
            onChange={(e) => setRatingFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-200 focus:outline-none"
          >
            <option value="all">All Ratings</option>
            <option value="5">5 Stars Only</option>
            <option value="4">4 Stars Only</option>
            <option value="3">3 Stars Only</option>
            <option value="2">2 Stars Only</option>
            <option value="1">1 Star Only</option>
          </select>

          {/* Verified Filter */}
          <select
            value={verifiedFilter}
            onChange={(e) => setVerifiedFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-200 focus:outline-none"
          >
            <option value="all">All Shoppers</option>
            <option value="true">Verified Buyers</option>
            <option value="false">Unverified</option>
          </select>
        </div>
      </div>

      {/* Reviews Stream / Cards */}
      <div className="space-y-3">
        {loading && reviews.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-xs bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-brand-600" />
            Loading customer reviews...
          </div>
        ) : reviews.length === 0 ? (
          <div className="p-12 text-center space-y-3 bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-800">
            <MessageSquare className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-700" />
            <h3 className="text-sm font-bold text-gray-900 dark:text-white">No reviews match your filters</h3>
            <p className="text-xs text-gray-500 max-w-sm mx-auto">
              Try adjusting your search criteria, star rating filter, or moderation status filter.
            </p>
          </div>
        ) : (
          reviews.map((review) => (
            <div
              key={review.id}
              className="p-5 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-xs space-y-4 hover:border-gray-300 dark:hover:border-gray-700 transition-all"
            >
              {/* Card Header: Product link, Stars, Status */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-100 dark:border-gray-800/80">
                {/* Product Info */}
                <div className="flex items-center gap-3">
                  <div className="w-11 h-11 rounded-xl overflow-hidden bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shrink-0">
                    {review.product_image ? (
                      <img
                        src={review.product_image}
                        alt={review.product_name}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center font-bold text-gray-400 text-xs">
                        P
                      </div>
                    )}
                  </div>

                  <div>
                    <Link
                      to={`/products/${review.product_slug || review.product_id}`}
                      target="_blank"
                      className="font-black text-xs text-gray-900 dark:text-white hover:text-brand-600 dark:hover:text-brand-400 transition-colors flex items-center gap-1 group"
                    >
                      <span className="line-clamp-1">{review.product_name}</span>
                      <ExternalLink className="w-3 h-3 text-gray-400 group-hover:text-brand-500 shrink-0" />
                    </Link>
                    <span className="text-[11px] text-gray-400 block mt-0.5">
                      Product ID: #{review.product_id}
                    </span>
                  </div>
                </div>

                {/* Rating & Status Badge */}
                <div className="flex items-center gap-2 self-start sm:self-auto">
                  {/* Stars Pill */}
                  <div className="flex items-center gap-1 bg-amber-50 dark:bg-amber-950/40 px-2.5 py-1 rounded-full border border-amber-200/60 dark:border-amber-900/40">
                    <div className="flex text-amber-400">
                      {[1, 2, 3, 4, 5].map((s) => (
                        <Star
                          key={s}
                          className={cn(
                            "w-3 h-3",
                            s <= review.rating ? "fill-amber-400 text-amber-400" : "text-gray-300 dark:text-gray-700"
                          )}
                        />
                      ))}
                    </div>
                    <span className="text-[11px] font-black text-amber-700 dark:text-amber-400 ml-0.5">
                      {review.rating}.0
                    </span>
                  </div>

                  {/* Status Pill */}
                  <span className={cn(
                    "px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wide uppercase",
                    review.status === 'approved' 
                      ? "bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300" 
                      : review.status === 'pending'
                      ? "bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300"
                      : "bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300"
                  )}>
                    {review.status}
                  </span>
                </div>
              </div>

              {/* Review Content & Reviewer Identity */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-brand-50 dark:bg-brand-950/60 text-brand-600 dark:text-brand-400 font-bold text-[11px] flex items-center justify-center">
                    {review.user_name[0]?.toUpperCase()}
                  </div>
                  <span className="text-xs font-bold text-gray-900 dark:text-white">
                    {review.user_name}
                  </span>
                  <span className="text-[11px] text-gray-400">({review.user_email})</span>

                  {review.is_verified_purchase && (
                    <span className="inline-flex items-center gap-0.5 text-[10px] font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-0.5 rounded-full">
                      <BadgeCheck className="w-3 h-3" />
                      Verified Purchase
                    </span>
                  )}

                  <span className="text-[10px] text-gray-400 ml-auto">
                    {review.created_at ? new Date(review.created_at).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'Recent'}
                  </span>
                </div>

                <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed pl-8">
                  "{review.review_text}"
                </p>
              </div>

              {/* Official Admin Reply Box (if present) */}
              {review.admin_reply && (
                <div className="ml-8 p-3.5 rounded-2xl bg-gray-50 dark:bg-gray-950/60 border border-gray-200 dark:border-gray-800 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-brand-600 dark:text-brand-400 text-[11px] flex items-center gap-1.5">
                      <CornerDownRight className="w-3.5 h-3.5" />
                      Official Store Response
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleOpenReplyModal(review)}
                        className="p-1 text-gray-400 hover:text-brand-600 transition-colors"
                        title="Edit response"
                      >
                        <Edit3 className="w-3 h-3" />
                      </button>
                      <button
                        onClick={() => handleDeleteReply(review.id)}
                        className="p-1 text-gray-400 hover:text-rose-600 transition-colors"
                        title="Delete response"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  <p className="text-gray-600 dark:text-gray-300 pl-5 text-[11px]">
                    {review.admin_reply}
                  </p>
                  {review.admin_reply_at && (
                    <span className="text-[10px] text-gray-400 pl-5 block">
                      Posted on {new Date(review.admin_reply_at).toLocaleDateString()}
                    </span>
                  )}
                </div>
              )}

              {/* Card Action Toolbar */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-gray-100 dark:border-gray-800/80 text-xs">
                {/* Status Toggle Actions */}
                <div className="flex items-center gap-1.5">
                  {review.status !== 'approved' && (
                    <button
                      onClick={() => handleUpdateStatus(review.id, 'approved')}
                      className="px-3 py-1.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 text-xs font-bold inline-flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Approve Review
                    </button>
                  )}

                  {review.status !== 'hidden' && (
                    <button
                      onClick={() => handleUpdateStatus(review.id, 'hidden')}
                      className="px-3 py-1.5 rounded-xl bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-rose-50 hover:text-rose-600 text-xs font-bold inline-flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      <EyeOff className="w-3.5 h-3.5" />
                      Hide Review
                    </button>
                  )}

                  {review.status === 'hidden' && (
                    <span className="text-[11px] text-rose-500 font-medium flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Currently hidden from buyers
                    </span>
                  )}
                </div>

                {/* Reply & Delete */}
                <div className="flex items-center gap-2 ml-auto">
                  <button
                    onClick={() => handleOpenReplyModal(review)}
                    className="px-3 py-1.5 rounded-xl bg-gray-100 dark:bg-gray-800 hover:bg-brand-50 dark:hover:bg-brand-950/60 hover:text-brand-600 dark:hover:text-brand-400 text-gray-700 dark:text-gray-300 text-xs font-bold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    {review.admin_reply ? 'Edit Response' : 'Reply as Store'}
                  </button>

                  <button
                    onClick={() => handleDeleteReview(review)}
                    className="p-1.5 text-gray-400 hover:text-rose-600 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30 transition-colors"
                    title="Permanently delete review"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between p-4 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 text-xs">
          <span className="text-gray-500">
            Showing Page <strong>{page}</strong> of <strong>{totalPages}</strong> ({totalItems} total reviews)
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchReviews(page - 1)}
              disabled={page <= 1}
              className="p-2 rounded-xl border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => fetchReviews(page + 1)}
              disabled={page >= totalPages}
              className="p-2 rounded-xl border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Official Response Composer Modal */}
      {replyingReview && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl w-full max-w-lg shadow-2xl overflow-hidden p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-100 dark:border-gray-800 pb-3">
              <div className="flex items-center gap-2">
                <MessageSquare className="w-5 h-5 text-brand-600" />
                <h3 className="font-black text-sm text-gray-900 dark:text-white">
                  Official Seller Response
                </h3>
              </div>
              <button
                onClick={() => setReplyingReview(null)}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quoted Customer Review Snippet */}
            <div className="p-3 rounded-2xl bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800 text-xs text-gray-600 dark:text-gray-300">
              <div className="font-bold text-gray-900 dark:text-white mb-1 flex items-center gap-1.5">
                <span>{replyingReview.user_name}</span>
                <span className="text-amber-500 font-normal">★ {replyingReview.rating}.0</span>
              </div>
              <p className="line-clamp-2 italic">"{replyingReview.review_text}"</p>
            </div>

            <form onSubmit={handleSaveReply} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-gray-700 dark:text-gray-300 mb-1">
                  Your Public Response *
                </label>
                <textarea
                  rows={4}
                  required
                  placeholder="Write an official, courteous response to this customer..."
                  value={replyText}
                  onChange={(e) => setReplyText(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500"
                />
              </div>

              {/* Quick Preset Phrases */}
              <div>
                <span className="text-[10px] font-bold text-gray-400 flex items-center gap-1 mb-1.5">
                  <Sparkles className="w-3 h-3 text-amber-500" /> Quick Reply Templates:
                </span>
                <div className="space-y-1">
                  {QUICK_REPLIES.map((preset, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => setReplyText(preset)}
                      className="w-full text-left text-[11px] p-2 rounded-xl bg-gray-50 dark:bg-gray-800/60 hover:bg-brand-50 hover:text-brand-600 dark:hover:bg-brand-950/40 text-gray-600 dark:text-gray-300 transition-colors"
                    >
                      {preset}
                    </button>
                  ))}
                </div>
              </div>

              <div className="pt-3 border-t border-gray-200 dark:border-gray-800 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setReplyingReview(null)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingReply}
                  className="px-5 py-2 rounded-xl text-xs font-bold bg-brand-600 hover:bg-brand-700 text-white shadow-md shadow-brand-600/20 disabled:opacity-50 inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  {isSubmittingReply ? 'Posting...' : 'Publish Response'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

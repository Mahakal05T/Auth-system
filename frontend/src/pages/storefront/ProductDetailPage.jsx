import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { demoProducts } from './HomePage';
import { productService, reviewService } from '../../services/api';
import { useCart } from '../../context/CartContext';
import { useWishlist } from '../../context/WishlistContext';
import { useAuth } from '../../context/AuthContext';
import { 
  Star, ShoppingCart, Heart, Shield, Truck, RotateCcw, 
  Check, ArrowLeft, Loader2, AlertTriangle, Sparkles, ShieldCheck, Trash2, Send, CornerDownRight 
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function ProductDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user, isAuthenticated } = useAuth();
  const [product, setProduct] = useState(null);
  const [selectedImage, setSelectedImage] = useState('');
  const [quantity, setQuantity] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const { addToCart } = useCart();
  const { isWishlisted, toggleWishlist } = useWishlist();

  // Reviews state
  const [reviews, setReviews] = useState([]);
  const [reviewsSummary, setReviewsSummary] = useState({
    average_rating: 5.0,
    total_reviews: 0,
    breakdown: { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 }
  });
  const [isLoadingReviews, setIsLoadingReviews] = useState(false);
  const [ratingInput, setRatingInput] = useState(5);
  const [commentInput, setCommentInput] = useState('');
  const [isSubmittingReview, setIsSubmittingReview] = useState(false);
  const [hoverRating, setHoverRating] = useState(0);

  const fetchReviews = async () => {
    try {
      setIsLoadingReviews(true);
      const data = await reviewService.getProductReviews(id);
      setReviews(data.reviews || []);
      setReviewsSummary({
        average_rating: data.average_rating || 5.0,
        total_reviews: data.total_reviews || 0,
        breakdown: data.breakdown || { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 }
      });
    } catch (err) {
      console.warn('Could not fetch reviews:', err);
    } finally {
      setIsLoadingReviews(false);
    }
  };

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    productService.getProduct(id)
      .then((data) => {
        if (isMounted && data) {
          setProduct(data);
          setSelectedImage(data.image || (data.images && data.images[0]?.image_url) || '');
        }
      })
      .catch((err) => {
        console.warn('Backend product fetch fallback:', err);
        const found = demoProducts.find(p => p.id === Number(id)) || demoProducts[0];
        if (isMounted) {
          setProduct(found);
          setSelectedImage(found.image);
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    fetchReviews();

    return () => { isMounted = false; };
  }, [id]);

  const handleAddToCart = () => {
    if (!product) return;
    addToCart(product, quantity);
    toast.success(`Added ${quantity} × ${product.name} to cart!`);
  };

  const handleBuyNow = () => {
    if (!product) return;
    addToCart(product, quantity);
    navigate('/checkout');
  };

  const handleSubmitReview = async (e) => {
    e.preventDefault();
    if (!isAuthenticated) {
      navigate(`/login?redirect=/products/${id}`);
      return;
    }

    if (!commentInput.trim() || commentInput.trim().length < 3) {
      toast.error('Please write at least a short comment for your review.');
      return;
    }

    try {
      setIsSubmittingReview(true);
      const res = await reviewService.submitReview(id, {
        rating: ratingInput,
        review_text: commentInput.trim()
      });
      toast.success(res.message || 'Thank you! Your review has been submitted.');
      setCommentInput('');
      fetchReviews();
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to submit review';
      toast.error(msg);
    } finally {
      setIsSubmittingReview(false);
    }
  };

  const handleDeleteReview = async (reviewId) => {
    if (!window.confirm('Are you sure you want to remove this review?')) return;
    try {
      await reviewService.deleteReview(id, reviewId);
      toast.success('Review removed');
      fetchReviews();
    } catch (err) {
      toast.error('Failed to delete review');
    }
  };

  if (isLoading) {
    return (
      <div className="py-24 text-center flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-10 h-10 text-brand-600 animate-spin" />
        <p className="text-xs text-gray-500 font-medium">Loading product specifications...</p>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="py-20 text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-rose-500 mx-auto" />
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">Product Not Found</h2>
        <p className="text-xs text-gray-500">The requested product could not be located in our catalog.</p>
        <Link
          to="/products"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full bg-brand-600 text-white font-bold text-xs"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Catalog
        </Link>
      </div>
    );
  }

  const images = product.images && product.images.length > 0 
    ? product.images.map(img => img.image_url) 
    : [product.image || 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80'];

  const discountPercent = product.discount_price 
    ? Math.round(((product.price - product.discount_price) / product.price) * 100) 
    : null;

  const currentPrice = product.discount_price || product.price;
  const stock = product.stock ?? 25;
  const isOutOfStock = stock <= 0;

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Breadcrumbs */}
      <div className="flex items-center gap-2 text-xs text-gray-500">
        <Link to="/" className="hover:text-brand-600">Home</Link>
        <span>/</span>
        <Link to="/products" className="hover:text-brand-600">Catalog</Link>
        <span>/</span>
        <span className="text-gray-900 dark:text-white font-medium truncate max-w-xs">{product.name}</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12 items-start">
        {/* Gallery */}
        <div className="space-y-4">
          <div className="aspect-square rounded-3xl overflow-hidden bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 p-6 flex items-center justify-center relative shadow-xs">
            {discountPercent && (
              <span className="absolute top-4 left-4 px-3 py-1 rounded-full text-xs font-black bg-rose-600 text-white uppercase tracking-wider shadow-sm">
                Save {discountPercent}%
              </span>
            )}
            <img
              src={selectedImage || images[0]}
              alt={product.name}
              className="w-full h-full object-contain hover:scale-105 transition-transform duration-300"
            />
          </div>

          {images.length > 1 && (
            <div className="flex items-center gap-3 overflow-x-auto pb-2">
              {images.map((imgUrl, idx) => (
                <button
                  key={idx}
                  onClick={() => setSelectedImage(imgUrl)}
                  className={`w-20 h-20 rounded-2xl overflow-hidden border-2 shrink-0 transition-all p-1 bg-white dark:bg-gray-900 ${
                    selectedImage === imgUrl ? 'border-brand-600 shadow-sm' : 'border-gray-200 dark:border-gray-800 opacity-70 hover:opacity-100'
                  }`}
                >
                  <img src={imgUrl} alt="thumbnail" className="w-full h-full object-contain" />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Product Details & Actions */}
        <div className="space-y-6">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-brand-600 uppercase tracking-wider mb-2">
              <span>{product.brand || 'Apex Exclusive'}</span>
              <span>•</span>
              <span>{product.category_name || product.category || 'Curated Item'}</span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-white leading-tight">
              {product.name}
            </h1>

            {/* Rating summary */}
            <div className="flex items-center gap-3 mt-3">
              <div className="flex items-center text-amber-500">
                {[...Array(5)].map((_, i) => (
                  <Star 
                    key={i} 
                    className={`w-4 h-4 ${i < Math.round(reviewsSummary.average_rating) ? 'fill-current' : 'text-gray-300 dark:text-gray-700'}`} 
                  />
                ))}
              </div>
              <span className="text-xs font-bold text-gray-900 dark:text-white">
                {reviewsSummary.average_rating.toFixed(1)}
              </span>
              <span className="text-xs text-gray-400">•</span>
              <button
                onClick={() => setActiveTab('reviews')}
                className="text-xs text-brand-600 hover:underline font-semibold"
              >
                {reviewsSummary.total_reviews} {reviewsSummary.total_reviews === 1 ? 'review' : 'reviews'}
              </button>
            </div>
          </div>

          {/* Pricing */}
          <div className="p-4 rounded-2xl bg-gray-50 dark:bg-gray-900/60 border border-gray-200/80 dark:border-gray-800 space-y-1">
            <div className="flex items-baseline gap-3">
              <span className="text-3xl font-black text-gray-900 dark:text-white font-mono">
                ${currentPrice.toFixed(2)}
              </span>
              {product.discount_price && (
                <span className="text-base text-gray-400 line-through font-mono">
                  ${product.price.toFixed(2)}
                </span>
              )}
            </div>
            <p className="text-[11px] text-emerald-600 font-medium flex items-center gap-1">
              <Check className="w-3.5 h-3.5" /> Price includes applicable local sales taxes & duty
            </p>
          </div>

          {/* Stock Availability */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${isOutOfStock ? 'bg-rose-500' : 'bg-emerald-500'}`} />
              <span className={`text-xs font-bold ${isOutOfStock ? 'text-rose-600' : 'text-emerald-600'}`}>
                {isOutOfStock ? 'Currently Out of Stock' : `In Stock (${stock} units available)`}
              </span>
            </div>
            <p className="text-xs text-gray-500 leading-relaxed">
              {product.description || 'Premium craftsmanship meets timeless performance. Includes 100% genuine warranty and priority courier delivery.'}
            </p>
          </div>

          {/* Quantity & CTA */}
          {!isOutOfStock && (
            <div className="space-y-4 pt-2">
              <div className="flex items-center gap-4">
                <div className="flex items-center border border-gray-300 dark:border-gray-700 rounded-xl overflow-hidden bg-white dark:bg-gray-900">
                  <button
                    onClick={() => setQuantity(Math.max(1, quantity - 1))}
                    className="px-3.5 py-2 text-sm font-bold hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    -
                  </button>
                  <span className="px-4 py-2 text-xs font-bold font-mono text-gray-900 dark:text-white">
                    {quantity}
                  </span>
                  <button
                    onClick={() => setQuantity(Math.min(stock, quantity + 1))}
                    className="px-3.5 py-2 text-sm font-bold hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    +
                  </button>
                </div>

                <button
                  onClick={() => toggleWishlist(product)}
                  className={`p-3 rounded-xl border transition-colors ${
                    isWishlisted(product?.id) 
                      ? 'border-rose-500 text-rose-500 bg-rose-50 dark:bg-rose-950/40' 
                      : 'border-gray-300 dark:border-gray-700 text-gray-600 hover:text-rose-500'
                  }`}
                  title="Wishlist"
                >
                  <Heart className={`w-5 h-5 ${isWishlisted(product?.id) ? 'fill-current' : ''}`} />
                </button>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <button
                  onClick={handleAddToCart}
                  className="flex-1 py-3.5 px-6 rounded-2xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-sm flex items-center justify-center gap-2 shadow-lg shadow-brand-600/30 transition-all"
                >
                  <ShoppingCart className="w-4 h-4" /> Add to Cart
                </button>
                <button
                  onClick={handleBuyNow}
                  className="py-3.5 px-8 rounded-2xl bg-gray-900 text-white dark:bg-white dark:text-gray-900 hover:bg-gray-800 dark:hover:bg-gray-100 font-bold text-sm flex items-center justify-center transition-colors text-center"
                >
                  Buy Now
                </button>
              </div>
            </div>
          )}

          {/* Guarantees */}
          <div className="grid grid-cols-3 gap-3 pt-4 border-t border-gray-200 dark:border-gray-800 text-center text-xs text-gray-500">
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-900 flex flex-col items-center gap-1">
              <Truck className="w-4 h-4 text-brand-600" />
              <span>Free Delivery</span>
            </div>
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-900 flex flex-col items-center gap-1">
              <RotateCcw className="w-4 h-4 text-emerald-600" />
              <span>30-Day Return</span>
            </div>
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-900 flex flex-col items-center gap-1">
              <Shield className="w-4 h-4 text-indigo-600" />
              <span>2-Year Warranty</span>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs: Specifications & Details & Customer Reviews */}
      <div className="mt-12 p-6 sm:p-8 rounded-3xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-6 shadow-xs">
        <div className="flex items-center gap-4 border-b border-gray-200 dark:border-gray-800 text-xs font-bold">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-3 border-b-2 transition-colors ${
              activeTab === 'overview' ? 'border-brand-600 text-brand-600' : 'border-transparent text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Product Overview
          </button>
          <button
            onClick={() => setActiveTab('specs')}
            className={`pb-3 border-b-2 transition-colors ${
              activeTab === 'specs' ? 'border-brand-600 text-brand-600' : 'border-transparent text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Specifications
          </button>
          <button
            onClick={() => setActiveTab('reviews')}
            className={`pb-3 border-b-2 transition-colors ${
              activeTab === 'reviews' ? 'border-brand-600 text-brand-600' : 'border-transparent text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Customer Reviews ({reviewsSummary.total_reviews})
          </button>
        </div>

        {activeTab === 'overview' && (
          <div className="space-y-4 text-xs sm:text-sm text-gray-600 dark:text-gray-300 leading-relaxed">
            <p>{product.description}</p>
            <ul className="list-disc pl-5 space-y-1.5 text-xs text-gray-500">
              <li>Engineered for premium performance and durability.</li>
              <li>Includes manufacturer warranty and authentic registration card.</li>
              <li>Certified RoHS, CE, and Energy Star compliant where applicable.</li>
            </ul>
          </div>
        )}

        {activeTab === 'specs' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 flex justify-between">
              <span className="text-gray-500">SKU</span>
              <span className="font-mono font-bold text-gray-900 dark:text-white">{product.sku || 'N/A'}</span>
            </div>
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 flex justify-between">
              <span className="text-gray-500">Brand</span>
              <span className="font-bold text-gray-900 dark:text-white">{product.brand || 'Apex'}</span>
            </div>
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 flex justify-between">
              <span className="text-gray-500">Category</span>
              <span className="font-bold text-gray-900 dark:text-white">{product.category_name || product.category || 'General'}</span>
            </div>
            <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 flex justify-between">
              <span className="text-gray-500">Warranty</span>
              <span className="font-bold text-gray-900 dark:text-white">24 Months Full Coverage</span>
            </div>
          </div>
        )}

        {activeTab === 'reviews' && (
          <div className="space-y-8">
            {/* Rating Breakdown & Aggregations */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 rounded-2xl bg-amber-50/40 dark:bg-amber-950/20 border border-amber-200/50 dark:border-amber-900/30 items-center">
              {/* Overall Score */}
              <div className="text-center md:text-left space-y-1">
                <div className="text-5xl font-black text-amber-500 font-mono">
                  {reviewsSummary.average_rating.toFixed(1)}
                </div>
                <div className="flex items-center justify-center md:justify-start gap-1 text-amber-500">
                  {[...Array(5)].map((_, i) => (
                    <Star 
                      key={i} 
                      className={`w-4 h-4 ${i < Math.round(reviewsSummary.average_rating) ? 'fill-current' : 'text-gray-300 dark:text-gray-700'}`} 
                    />
                  ))}
                </div>
                <p className="text-xs text-gray-500">
                  Based on {reviewsSummary.total_reviews} verified customer reviews
                </p>
              </div>

              {/* Star Distribution Bars */}
              <div className="md:col-span-2 space-y-2 text-xs">
                {[5, 4, 3, 2, 1].map((st) => {
                  const count = reviewsSummary.breakdown[st] || 0;
                  const percent = reviewsSummary.total_reviews > 0 
                    ? Math.round((count / reviewsSummary.total_reviews) * 100) 
                    : 0;

                  return (
                    <div key={st} className="flex items-center gap-3">
                      <span className="w-12 text-gray-600 dark:text-gray-400 font-bold flex items-center gap-1">
                        {st} <Star className="w-3 h-3 fill-amber-500 text-amber-500" />
                      </span>
                      <div className="flex-1 h-2 rounded-full bg-gray-200 dark:bg-gray-800 overflow-hidden">
                        <div 
                          className="h-full bg-amber-500 rounded-full transition-all duration-500" 
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                      <span className="w-10 text-right text-gray-500 font-mono text-[11px]">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Write a Review Section */}
            <div className="p-6 rounded-2xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 space-y-4">
              <h3 className="font-black text-sm text-gray-900 dark:text-white uppercase tracking-wider">
                Share Your Customer Feedback
              </h3>

              {!isAuthenticated ? (
                <div className="p-4 rounded-xl bg-gray-50 dark:bg-gray-800/40 text-xs flex flex-col sm:flex-row items-center justify-between gap-3">
                  <span className="text-gray-600 dark:text-gray-400">
                    Sign in to publish a product review and receive a Verified Buyer badge.
                  </span>
                  <Link
                    to={`/login?redirect=/products/${id}`}
                    className="px-4 py-2 rounded-xl bg-brand-600 text-white font-bold shrink-0"
                  >
                    Sign In to Review
                  </Link>
                </div>
              ) : (
                <form onSubmit={handleSubmitReview} className="space-y-4 text-xs">
                  <div>
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1.5">
                      Your Rating *
                    </label>
                    <div className="flex items-center gap-1.5">
                      {[1, 2, 3, 4, 5].map((star) => (
                        <button
                          key={star}
                          type="button"
                          onMouseEnter={() => setHoverRating(star)}
                          onMouseLeave={() => setHoverRating(0)}
                          onClick={() => setRatingInput(star)}
                          className="p-1 text-amber-500 hover:scale-110 transition-transform"
                        >
                          <Star 
                            className={`w-6 h-6 ${
                              (hoverRating || ratingInput) >= star 
                                ? 'fill-current text-amber-500' 
                                : 'text-gray-300 dark:text-gray-700'
                            }`} 
                          />
                        </button>
                      ))}
                      <span className="ml-2 font-bold text-gray-700 dark:text-gray-300 font-mono">
                        {hoverRating || ratingInput} / 5 Stars
                      </span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-gray-600 dark:text-gray-400 font-medium mb-1.5">
                      Review Comments *
                    </label>
                    <textarea
                      rows={3}
                      required
                      value={commentInput}
                      onChange={(e) => setCommentInput(e.target.value)}
                      placeholder="What did you like or dislike about this product? How was the build quality and performance?"
                      className="w-full px-3.5 py-2.5 rounded-xl border border-gray-300 dark:border-gray-700 bg-transparent text-gray-900 dark:text-white focus:outline-none focus:border-brand-500 leading-relaxed"
                    />
                  </div>

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={isSubmittingReview}
                      className="px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold flex items-center gap-1.5 transition-colors disabled:opacity-60 shadow-xs"
                    >
                      <Send className="w-3.5 h-3.5" />
                      {isSubmittingReview ? 'Submitting...' : 'Post Review'}
                    </button>
                  </div>
                </form>
              )}
            </div>

            {/* Reviews Stream */}
            <div className="space-y-4">
              <h3 className="font-black text-sm text-gray-900 dark:text-white uppercase tracking-wider">
                Customer Testimonials ({reviews.length})
              </h3>

              {isLoadingReviews ? (
                <div className="py-8 text-center">
                  <Loader2 className="w-6 h-6 text-brand-600 animate-spin mx-auto" />
                </div>
              ) : reviews.length === 0 ? (
                <div className="p-8 text-center rounded-2xl bg-gray-50 dark:bg-gray-800/30 text-xs text-gray-500">
                  No customer reviews yet. Be the first to review this product!
                </div>
              ) : (
                <div className="space-y-3">
                  {reviews.map((rev) => (
                    <div
                      key={rev.id}
                      className="p-5 rounded-2xl bg-gray-50/70 dark:bg-gray-800/40 border border-gray-200/50 dark:border-gray-800 space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-brand-100 dark:bg-brand-950 text-brand-600 font-bold flex items-center justify-center text-xs">
                            {rev.user_name.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-gray-900 dark:text-white">{rev.user_name}</span>
                              {rev.is_verified_purchase && (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300 flex items-center gap-1 border border-emerald-200 dark:border-emerald-800/40">
                                  <ShieldCheck className="w-3 h-3" /> Verified Buyer
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <div className="flex items-center text-amber-500">
                                {[...Array(5)].map((_, i) => (
                                  <Star
                                    key={i}
                                    className={`w-3 h-3 ${i < rev.rating ? 'fill-current' : 'text-gray-300 dark:text-gray-700'}`}
                                  />
                                ))}
                              </div>
                              <span className="text-gray-400 text-[11px] font-mono">• {rev.created_at}</span>
                            </div>
                          </div>
                        </div>

                        {/* Delete action if owner or admin */}
                        {(user?.id === rev.user_id || user?.role === 'admin') && (
                          <button
                            onClick={() => handleDeleteReview(rev.id)}
                            className="p-1.5 text-gray-400 hover:text-rose-500 transition-colors"
                            title="Delete this review"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>

                      <p className="text-gray-600 dark:text-gray-300 leading-relaxed pl-11">
                        {rev.review_text}
                      </p>

                      {/* Official Seller Response */}
                      {rev.admin_reply && (
                        <div className="ml-11 mt-2.5 p-3 rounded-xl bg-white dark:bg-gray-900 border border-brand-200 dark:border-brand-900/50 space-y-1">
                          <span className="font-bold text-brand-600 dark:text-brand-400 text-[10px] flex items-center gap-1">
                            <CornerDownRight className="w-3 h-3" /> Official Store Response
                          </span>
                          <p className="text-gray-600 dark:text-gray-300 text-[11px] pl-4">
                            "{rev.admin_reply}"
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

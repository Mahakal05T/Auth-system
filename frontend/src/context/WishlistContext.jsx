import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { wishlistService } from '../services/api';
import { useAuth } from './AuthContext';
import { useCart } from './CartContext';
import toast from 'react-hot-toast';

const WishlistContext = createContext();

const GUEST_WISHLIST_KEY = 'apex_guest_wishlist';

export function WishlistProvider({ children }) {
  const { isAuthenticated } = useAuth();
  const { refreshCart } = useCart();
  const [items, setItems] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  // Sync / refresh wishlist
  const refreshWishlist = useCallback(async () => {
    if (isAuthenticated) {
      try {
        setIsLoading(true);
        // Check if there are guest items to merge
        const savedGuest = localStorage.getItem(GUEST_WISHLIST_KEY);
        if (savedGuest) {
          try {
            const parsed = JSON.parse(savedGuest);
            if (Array.isArray(parsed) && parsed.length > 0) {
              const merged = await wishlistService.syncGuestWishlist(parsed);
              localStorage.removeItem(GUEST_WISHLIST_KEY);
              if (merged && merged.items) {
                setItems(merged.items);
                return;
              }
            }
          } catch (e) {
            localStorage.removeItem(GUEST_WISHLIST_KEY);
          }
        }

        const serverData = await wishlistService.getWishlist();
        if (serverData && serverData.items) {
          setItems(serverData.items);
        }
      } catch (err) {
        console.warn('Could not fetch server wishlist:', err);
      } finally {
        setIsLoading(false);
      }
    } else {
      try {
        const saved = localStorage.getItem(GUEST_WISHLIST_KEY);
        if (saved) {
          const parsed = JSON.parse(saved);
          if (Array.isArray(parsed)) {
            setItems(parsed);
          }
        }
      } catch (e) {
        console.warn('Invalid guest wishlist data');
      }
    }
  }, [isAuthenticated]);

  useEffect(() => {
    refreshWishlist();
  }, [refreshWishlist]);

  // Check if product is currently wishlisted
  const isWishlisted = useCallback((productId) => {
    if (!productId) return false;
    return items.some(item => (item.product_id || item.id) === Number(productId));
  }, [items]);

  // Toggle wishlist state
  const toggleWishlist = async (product) => {
    if (!product) return;
    const productId = product.product_id || product.id;
    const currentlyWishlisted = isWishlisted(productId);

    if (isAuthenticated) {
      try {
        setIsLoading(true);
        if (currentlyWishlisted) {
          await wishlistService.removeFromWishlist(productId);
          setItems(prev => prev.filter(i => (i.product_id || i.id) !== Number(productId)));
          toast.success(`Removed "${product.name}" from wishlist`);
        } else {
          const res = await wishlistService.addToWishlist(productId);
          if (res.wishlist?.items) {
            setItems(res.wishlist.items);
          } else {
            setItems(prev => [{ ...product, product_id: productId }, ...prev]);
          }
          toast.success(`Saved "${product.name}" to wishlist`);
        }
      } catch (err) {
        toast.error('Failed to update wishlist');
      } finally {
        setIsLoading(false);
      }
    } else {
      // Guest management
      try {
        const saved = localStorage.getItem(GUEST_WISHLIST_KEY);
        let list = saved ? JSON.parse(saved) : [];
        if (!Array.isArray(list)) list = [];

        if (currentlyWishlisted) {
          list = list.filter(i => (i.product_id || i.id) !== Number(productId));
          setItems(list);
          localStorage.setItem(GUEST_WISHLIST_KEY, JSON.stringify(list));
          toast.success(`Removed "${product.name}" from wishlist`);
        } else {
          const newItem = {
            id: `guest-${Date.now()}`,
            product_id: productId,
            name: product.name,
            price: product.discount_price || product.price,
            original_price: product.discount_price ? product.price : null,
            image: product.image,
            category: product.category_name || product.category || 'General',
            stock: product.stock || 50,
            in_stock: true
          };
          list.unshift(newItem);
          setItems(list);
          localStorage.setItem(GUEST_WISHLIST_KEY, JSON.stringify(list));
          toast.success(`Saved "${product.name}" to wishlist`);
        }
      } catch (e) {
        toast.error('Failed to update local wishlist');
      }
    }
  };

  // Move product from wishlist to cart
  const moveToCart = async (product) => {
    if (!product) return;
    const productId = product.product_id || product.id;

    if (isAuthenticated) {
      try {
        setIsLoading(true);
        const res = await wishlistService.moveToCart(productId);
        if (res.wishlist?.items) {
          setItems(res.wishlist.items);
        } else {
          setItems(prev => prev.filter(i => (i.product_id || i.id) !== Number(productId)));
        }
        await refreshCart();
        toast.success(res.message || `Moved "${product.name}" to cart!`);
      } catch (err) {
        const msg = err.response?.data?.error || 'Failed to move to cart';
        toast.error(msg);
      } finally {
        setIsLoading(false);
      }
    } else {
      // Guest move to cart
      try {
        toggleWishlist(product);
        // Dispatch to cart via local storage
        const GUEST_CART_KEY = 'apex_guest_cart';
        const savedCart = localStorage.getItem(GUEST_CART_KEY);
        let cartItems = savedCart ? JSON.parse(savedCart) : [];
        if (!Array.isArray(cartItems)) cartItems = [];

        const existingIdx = cartItems.findIndex(i => (i.product_id || i.id) === productId);
        if (existingIdx > -1) {
          cartItems[existingIdx].quantity += 1;
        } else {
          cartItems.push({
            id: `guest-${Date.now()}`,
            product_id: productId,
            name: product.name,
            price: product.price,
            discount_price: product.discount_price,
            image: product.image,
            quantity: 1,
            stock: product.stock || 50
          });
        }
        localStorage.setItem(GUEST_CART_KEY, JSON.stringify(cartItems));
        await refreshCart();
        toast.success(`Moved "${product.name}" to cart!`);
      } catch (e) {
        toast.error('Failed to move item to cart');
      }
    }
  };

  // Remove by product ID
  const removeFromWishlist = async (productId) => {
    const item = items.find(i => (i.product_id || i.id) === Number(productId));
    if (item) {
      await toggleWishlist(item);
    }
  };

  return (
    <WishlistContext.Provider value={{
      items,
      wishlistItems: items,
      wishlistCount: items.length,
      isWishlisted,
      toggleWishlist,
      moveToCart,
      removeFromWishlist,
      refreshWishlist,
      isLoading
    }}>
      {children}
    </WishlistContext.Provider>
  );
}

export function useWishlist() {
  const context = useContext(WishlistContext);
  if (!context) {
    throw new Error('useWishlist must be used within a WishlistProvider');
  }
  return context;
}

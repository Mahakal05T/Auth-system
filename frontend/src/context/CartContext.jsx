import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { cartService } from '../services/api';
import { useAuth } from './AuthContext';
import toast from 'react-hot-toast';

const CartContext = createContext();

const GUEST_CART_KEY = 'apex_guest_cart';

export function CartProvider({ children }) {
  const { isAuthenticated } = useAuth();
  const [cart, setCart] = useState({
    items: [],
    total_items: 0,
    subtotal: 0.0,
    shipping_fee: 0.0,
    total: 0.0,
    free_shipping_threshold: 49.0,
    amount_for_free_shipping: 49.0
  });
  const [isLoading, setIsLoading] = useState(false);

  // Helper to recompute guest cart from localStorage items
  const computeGuestCart = useCallback((guestItems) => {
    let subtotal = 0.0;
    let totalItems = 0;

    const items = guestItems.map((item, idx) => {
      const unitPrice = item.discount_price && item.discount_price < item.price 
        ? item.discount_price 
        : item.price;
      const itemTotal = unitPrice * item.quantity;
      subtotal += itemTotal;
      totalItems += item.quantity;

      return {
        id: item.id || `guest-${idx}`,
        product_id: item.product_id || item.id,
        name: item.name,
        image: item.image,
        quantity: item.quantity,
        unit_price: unitPrice,
        regular_price: item.price,
        total_price: itemTotal,
        stock: item.stock || 50,
        is_out_of_stock: (item.stock || 50) < item.quantity
      };
    });

    const shippingFee = subtotal >= 49.0 || items.length === 0 ? 0.0 : 9.99;
    const total = subtotal + shippingFee;

    return {
      items,
      total_items: totalItems,
      subtotal: Math.round(subtotal * 100) / 100,
      shipping_fee: Math.round(shippingFee * 100) / 100,
      total: Math.round(total * 100) / 100,
      free_shipping_threshold: 49.0,
      amount_for_free_shipping: Math.max(0, Math.round((49.0 - subtotal) * 100) / 100)
    };
  }, []);

  // Fetch or sync cart
  const refreshCart = useCallback(async () => {
    if (isAuthenticated) {
      try {
        setIsLoading(true);
        // Check if there is a guest cart to merge
        const savedGuest = localStorage.getItem(GUEST_CART_KEY);
        if (savedGuest) {
          try {
            const parsed = JSON.parse(savedGuest);
            if (Array.isArray(parsed) && parsed.length > 0) {
              const mergedCart = await cartService.syncGuestCart(parsed);
              localStorage.removeItem(GUEST_CART_KEY);
              if (mergedCart) setCart(mergedCart);
              return;
            }
          } catch (e) {
            localStorage.removeItem(GUEST_CART_KEY);
          }
        }

        const serverCart = await cartService.getCart();
        if (serverCart) {
          setCart(serverCart);
        }
      } catch (err) {
        console.warn('Could not fetch server cart:', err);
      } finally {
        setIsLoading(false);
      }
    } else {
      // Load guest cart
      try {
        const saved = localStorage.getItem(GUEST_CART_KEY);
        if (saved) {
          const parsed = JSON.parse(saved);
          if (Array.isArray(parsed)) {
            setCart(computeGuestCart(parsed));
          }
        }
      } catch (e) {
        console.warn('Invalid guest cart data');
      }
    }
  }, [isAuthenticated, computeGuestCart]);

  useEffect(() => {
    refreshCart();
  }, [refreshCart]);

  // Add product to cart
  const addToCart = async (product, quantity = 1) => {
    if (!product) return;
    const productId = product.product_id || product.id;

    if (isAuthenticated) {
      try {
        setIsLoading(true);
        const res = await cartService.addToCart(productId, quantity);
        if (res.cart) {
          setCart(res.cart);
        }
        toast.success(res.message || `Added "${product.name}" to cart!`);
      } catch (err) {
        const msg = err.response?.data?.error || 'Failed to add item to cart';
        toast.error(msg);
      } finally {
        setIsLoading(false);
      }
    } else {
      // Guest cart management in localStorage
      try {
        const saved = localStorage.getItem(GUEST_CART_KEY);
        let items = saved ? JSON.parse(saved) : [];
        if (!Array.isArray(items)) items = [];

        const existingIdx = items.findIndex(i => (i.product_id || i.id) === productId);
        if (existingIdx > -1) {
          items[existingIdx].quantity += quantity;
        } else {
          items.push({
            id: `guest-${Date.now()}`,
            product_id: productId,
            name: product.name,
            price: product.price,
            discount_price: product.discount_price,
            image: product.image,
            quantity: quantity,
            stock: product.stock || 50
          });
        }
        localStorage.setItem(GUEST_CART_KEY, JSON.stringify(items));
        setCart(computeGuestCart(items));
        toast.success(`Added "${product.name}" to cart!`);
      } catch (e) {
        toast.error('Failed to update local cart');
      }
    }
  };

  // Update item quantity
  const updateQuantity = async (itemId, newQuantity) => {
    if (newQuantity < 1) {
      return removeFromCart(itemId);
    }

    if (isAuthenticated) {
      try {
        setIsLoading(true);
        const updated = await cartService.updateItem(itemId, newQuantity);
        if (updated) setCart(updated);
      } catch (err) {
        toast.error(err.response?.data?.error || 'Failed to update quantity');
      } finally {
        setIsLoading(false);
      }
    } else {
      try {
        const saved = localStorage.getItem(GUEST_CART_KEY);
        let items = saved ? JSON.parse(saved) : [];
        items = items.map(item => {
          if (item.id === itemId || item.product_id === itemId) {
            return { ...item, quantity: newQuantity };
          }
          return item;
        });
        localStorage.setItem(GUEST_CART_KEY, JSON.stringify(items));
        setCart(computeGuestCart(items));
      } catch (e) {
        toast.error('Failed to update quantity');
      }
    }
  };

  // Remove single item
  const removeFromCart = async (itemId) => {
    if (isAuthenticated) {
      try {
        setIsLoading(true);
        const updated = await cartService.removeItem(itemId);
        if (updated) setCart(updated);
        toast.success('Item removed from cart');
      } catch (err) {
        toast.error(err.response?.data?.error || 'Failed to remove item');
      } finally {
        setIsLoading(false);
      }
    } else {
      try {
        const saved = localStorage.getItem(GUEST_CART_KEY);
        let items = saved ? JSON.parse(saved) : [];
        items = items.filter(item => item.id !== itemId && item.product_id !== itemId);
        localStorage.setItem(GUEST_CART_KEY, JSON.stringify(items));
        setCart(computeGuestCart(items));
        toast.success('Item removed from cart');
      } catch (e) {
        toast.error('Failed to remove item');
      }
    }
  };

  // Clear entire cart
  const clearCart = async () => {
    if (isAuthenticated) {
      try {
        setIsLoading(true);
        await cartService.clearCart();
        setCart({
          items: [],
          total_items: 0,
          subtotal: 0.0,
          shipping_fee: 0.0,
          total: 0.0,
          free_shipping_threshold: 49.0,
          amount_for_free_shipping: 49.0
        });
      } catch (err) {
        console.warn('Could not clear server cart:', err);
      } finally {
        setIsLoading(false);
      }
    } else {
      localStorage.removeItem(GUEST_CART_KEY);
      setCart({
        items: [],
        total_items: 0,
        subtotal: 0.0,
        shipping_fee: 0.0,
        total: 0.0,
        free_shipping_threshold: 49.0,
        amount_for_free_shipping: 49.0
      });
    }
  };

  return (
    <CartContext.Provider value={{
      cart,
      items: cart.items,
      totalItems: cart.total_items,
      subtotal: cart.subtotal,
      shippingFee: cart.shipping_fee,
      total: cart.total,
      amountForFreeShipping: cart.amount_for_free_shipping,
      freeShippingThreshold: cart.free_shipping_threshold,
      isLoading,
      addToCart,
      updateQuantity,
      removeFromCart,
      clearCart,
      refreshCart
    }}>
      {children}
    </CartContext.Provider>
  );
}

export function useCart() {
  const context = useContext(CartContext);
  if (!context) {
    throw new Error('useCart must be used within a CartProvider');
  }
  return context;
}

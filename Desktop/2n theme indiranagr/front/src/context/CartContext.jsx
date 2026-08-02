"use client";

import React, { createContext, useState, useEffect } from 'react';

export const CartContext = createContext();

export const CartProvider = ({ children }) => {
  const [cartItems, setCartItems] = useState([]);
  const [isCartOpen, setIsCartOpen] = useState(false);
  const [isCartLoaded, setIsCartLoaded] = useState(false);
  
  // Load from local storage on init
  useEffect(() => {
    const savedCart = localStorage.getItem('vapes_cart');
    if (savedCart) {
      try {
        setCartItems(JSON.parse(savedCart));
      } catch (e) {
        console.error("Could not parse cart data");
      }
    }
    setIsCartLoaded(true);
  }, []);

  // Save to local storage on change
  useEffect(() => {
    if (isCartLoaded) {
      localStorage.setItem('vapes_cart', JSON.stringify(cartItems));
    }
  }, [cartItems, isCartLoaded]);

  const addToCart = (product, quantity, flavour = null) => {
    let maxStock = product.stock || 0;
    if (flavour && product.flavours) {
      const fObj = product.flavours.find(f => f.flavour_name === flavour);
      if (fObj) maxStock = fObj.stock;
    }

    const existingItem = cartItems.find(item => item.product_id === product.id && item.flavour === flavour);
    const currentQty = existingItem ? existingItem.quantity : 0;

    if (currentQty + quantity > maxStock) {
      if (currentQty < maxStock) {
        const remaining = maxStock - currentQty;
        setCartItems(prev => {
          const newCart = [...prev];
          const idx = newCart.findIndex(item => item.product_id === product.id && item.flavour === flavour);
          newCart[idx] = { ...newCart[idx], quantity: maxStock, maxStock };
          return newCart;
        });
        return { success: false, message: `Only ${remaining} more available in stock. Added the rest.` };
      }
      return { success: false, message: `Cannot add more. Maximum stock of ${maxStock} reached.` };
    }

    setCartItems(prev => {
      const existingItemIndex = prev.findIndex(
        item => item.product_id === product.id && item.flavour === flavour
      );

      if (existingItemIndex >= 0) {
        const newCart = [...prev];
        const existItem = newCart[existingItemIndex];
        newCart[existingItemIndex] = {
          ...existItem,
          quantity: existItem.quantity + quantity,
          maxStock
        };
        return newCart;
      }

      return [...prev, {
        product_id: product.id,
        slug: product.slug,
        name: product.name,
        price: product.price,
        image: product.primary_image,
        quantity: quantity,
        flavour,
        maxStock
      }];
    });

    return { success: true };
  };

  const removeFromCart = (productId, flavour) => {
    setCartItems(prev => prev.filter(
      item => !(item.product_id === productId && item.flavour === flavour)
    ));
  };

  const updateQuantity = (productId, flavour, newQuantity) => {
    if (newQuantity <= 0) {
      removeFromCart(productId, flavour);
      return;
    }
    
    setCartItems(prev => prev.map(item => {
      if (item.product_id === productId && item.flavour === flavour) {
        const maxStock = item.maxStock !== undefined ? item.maxStock : Infinity;
        return { ...item, quantity: Math.min(newQuantity, maxStock) };
      }
      return item;
    }));
  };

  const clearCart = () => {
    setCartItems([]);
  };

  const cartTotal = cartItems.reduce((total, item) => total + (item.price * item.quantity), 0);
  const cartCount = cartItems.reduce((count, item) => count + item.quantity, 0);

  return (
    <CartContext.Provider value={{
      cartItems,
      addToCart,
      removeFromCart,
      updateQuantity,
      clearCart,
      cartTotal,
      cartCount,
      isCartOpen,
      setIsCartOpen
    }}>
      {children}
    </CartContext.Provider>
  );
};

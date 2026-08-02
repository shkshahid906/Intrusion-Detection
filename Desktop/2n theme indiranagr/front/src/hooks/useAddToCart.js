"use client";

import { useContext } from 'react';
import { CartContext } from '../context/CartContext';
import { toast } from 'react-toastify';

export const useAddToCart = () => {
  const { addToCart, setIsCartOpen } = useContext(CartContext);

  const handleAddToCart = (product, flavour) => {
    if (product.flavours && product.flavours.length > 0 && !flavour) {
      toast.warning("Please select a flavour first");
      return;
    }
    addToCart(product, 1, flavour);
    toast.success(`${product.name} added to cart`);
    setIsCartOpen(true);
  };

  return handleAddToCart;
};

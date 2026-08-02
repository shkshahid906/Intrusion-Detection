"use client";

import React, { useContext } from 'react';
import { CartContext } from '../../context/CartContext';
import { useRouter } from 'next/navigation';
import './CartDrawer.css';

const CartDrawer = () => {
  const { isCartOpen, setIsCartOpen, cartItems, removeFromCart, updateQuantity, cartTotal } = useContext(CartContext);
  const navigate = useRouter();

  if (!isCartOpen) return null;

  return (
    <>
      <div className="cart-overlay" onClick={() => setIsCartOpen(false)}></div>
      <div className={`cart-drawer ${isCartOpen ? 'open' : ''}`}>
        <div className="cart-header">
          <h2>Your Cart</h2>
          <button className="close-cart" onClick={() => setIsCartOpen(false)}>
            <i className="fas fa-times"></i>
          </button>
        </div>

        <div className="cart-items">
          {cartItems.length === 0 ? (
            <div className="empty-cart">
              <i className="fas fa-shopping-basket"></i>
              <p>Your cart is empty.</p>
              <button className="btn-primary" onClick={() => {
                setIsCartOpen(false);
                navigate.push('/#products');
              }}>Continue Shopping</button>
            </div>
          ) : (
            cartItems.map((item, index) => (
              <div className="cart-item" key={index}>
                <div className="cart-item-image">
                  <img loading="lazy" src={`${item.image}`} alt={item.name} />
                </div>
                <div className="cart-item-details">
                  <h4>{item.name}</h4>
                  {item.flavour && <p className="cart-item-flavour">Flavour: {item.flavour}</p>}
                  <p className="cart-item-price">₹{item.price}</p>
                  
                  <div className="cart-item-actions">
                    <div className="quantity-controls">
                      <button 
                        onClick={() => item.quantity > 1 && updateQuantity(item.product_id, item.flavour, item.quantity - 1)}
                        disabled={item.quantity <= 1}
                        style={item.quantity <= 1 ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
                      >-</button>
                      <span>{item.quantity}</span>
                      <button 
                        onClick={() => updateQuantity(item.product_id, item.flavour, item.quantity + 1)}
                        disabled={item.maxStock !== undefined && item.quantity >= item.maxStock}
                        style={item.maxStock !== undefined && item.quantity >= item.maxStock ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
                      >+</button>
                    </div>
                    <button className="remove-item" onClick={() => removeFromCart(item.product_id, item.flavour)}>
                      <i className="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {cartItems.length > 0 && (
          <div className="cart-footer">
            <div className="cart-total">
              <span>Total</span>
              <span>₹{cartTotal}</span>
            </div>
            <button className="btn-primary checkout-btn" onClick={() => {
              setIsCartOpen(false);
              navigate.push('/checkout');
            }}>
              Proceed to Checkout
            </button>
          </div>
        )}
      </div>
    </>
  );
};

export default CartDrawer;

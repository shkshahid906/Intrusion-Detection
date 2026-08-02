"use client";

﻿import React, { useState, useContext, useEffect } from 'react';
import { CartContext } from '../../../context/CartContext';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import api from '../../../services/api';
import { toast } from 'react-toastify';
import './Checkout.css';

const Checkout = () => {
  const { cartItems, cartTotal, clearCart, updateQuantity, removeFromCart, isCartLoaded } = useContext(CartContext);
  const navigate = useRouter();
  
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    address: '',
    pin_code: '',
  });
  const [location, setLocation] = useState(null);
  const [waSettings, setWaSettings] = useState(null);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [addressMethod, setAddressMethod] = useState('manual'); // 'manual' or 'fetch'
  const [pinInfo, setPinInfo] = useState(null);
  const [isFetchingPin, setIsFetchingPin] = useState(false);
  const [isFetchingLocation, setIsFetchingLocation] = useState(false);

  const [orderSuccess, setOrderSuccess] = useState(false);
  const [waRedirectUrl, setWaRedirectUrl] = useState('');
  const [orderIdDisplay, setOrderIdDisplay] = useState('');

  useEffect(() => {
    window.scrollTo(0, 0);
    
    if (isCartLoaded && cartItems.length === 0 && !orderSuccess) {
      navigate.push('/');
    }
    
    // Fetch WA settings for checkout
    const fetchWa = async () => {
      try {
        const res = await api.get('/cms/whatsapp');
        if (res.data.success) {
          setWaSettings(res.data.whatsapp);
        }
      } catch (err) {
        console.error("Failed to load WA settings", err);
      }
    };
    fetchWa();
  }, [cartItems, navigate, isCartLoaded, orderSuccess]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    
    if (name === 'phone') {
      const numericValue = value.replace(/\D/g, '');
      if (numericValue.length <= 10) {
        setFormData(prev => ({ ...prev, [name]: numericValue }));
      }
      return;
    }
    
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handlePinChange = async (e) => {
    const pin = e.target.value.replace(/\D/g, '');
    if (pin.length > 6) return;
    
    setFormData(prev => ({ ...prev, pin_code: pin }));
    
    if (pin.length === 6) {
      setIsFetchingPin(true);
      try {
        const res = await fetch(`https://api.postalpincode.in/pincode/${pin}`);
        const data = await res.json();
        if (data && data[0].Status === "Success") {
          const postOffice = data[0].PostOffice[0];
          setPinInfo(`${postOffice.Name}, ${postOffice.District}, ${postOffice.State}`);
        } else {
          setPinInfo("Invalid PIN Code");
        }
      } catch (err) {
        setPinInfo("Could not verify PIN");
      }
      setIsFetchingPin(false);
    } else {
      setPinInfo(null);
    }
  };

  const handleGetLocation = () => {
    if ("geolocation" in navigator) {
      setIsFetchingLocation(true);
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const lat = position.coords.latitude;
          const lng = position.coords.longitude;
          try {
            const res = await fetch(`https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json`, { headers: { 'Accept-Language': 'en-US,en;q=0.9' } });
            const data = await res.json();
            
            const fetchedPin = data.address?.postcode || '';
            const fetchedAddress = data.display_name || `Lat: ${lat.toFixed(4)}, Lng: ${lng.toFixed(4)}`;
            
            setLocation({
              lat,
              lng,
              address: fetchedAddress
            });
            setFormData(prev => ({ ...prev, address: fetchedAddress, pin_code: fetchedPin }));
            toast.success("Location captured successfully");
          } catch (err) {
            const fallbackAddr = `Lat: ${lat.toFixed(4)}, Lng: ${lng.toFixed(4)}`;
            setLocation({ lat, lng, address: fallbackAddr });
            setFormData(prev => ({ ...prev, address: fallbackAddr }));
            toast.success("Location captured successfully");
          }
          setIsFetchingLocation(false);
        },
        (error) => {
          toast.error("Could not capture location. Please ensure location services are enabled.");
          setIsFetchingLocation(false);
        }
      );
    } else {
      toast.error("Geolocation is not supported by your browser");
    }
  };

  const handlePlaceOrder = async (e) => {
    e.preventDefault();
    
    // Explicit JS Validation for all required fields to ensure mobile compatibility
    if (!formData.name.trim()) {
      toast.error("Please enter your Full Name.");
      return;
    }
    
    if (!formData.phone || formData.phone.length < 10) {
      toast.error("Please enter a valid 10-digit WhatsApp Number.");
      return;
    }

    if (addressMethod === 'manual') {
      if (!formData.address.trim()) {
        toast.error("Please enter your Delivery Address.");
        return;
      }
      if (!formData.pin_code || formData.pin_code.length !== 6) {
        toast.error("Please enter a valid 6-digit PIN Code.");
        return;
      }
    } else if (addressMethod === 'fetch' && !location) {
      toast.error("Please click 'Fetch Location' to capture your delivery location before placing the order.");
      return;
    }

    if (!waSettings || !waSettings.business_number) {
      toast.error("Checkout is currently unavailable. Please contact support.");
      return;
    }

    setIsSubmitting(true);

    try {
      // 1. Save order to DB
      const orderPayload = {
        name: formData.name,
        phone: formData.phone,
        address: formData.address,
        pin: formData.pin_code,
        lat: location ? location.lat : null,
        lng: location ? location.lng : null,
        location: location ? `https://maps.google.com/?q=${location.lat},${location.lng}` : '',
        totalAmount: cartTotal,
                cartItems: cartItems.map(item => ({
          product_id: item.product_id || item.id,
          name: item.name,
          flavour: item.flavour || '',
          quantity: item.quantity,
          price: item.price
        }))
      };

      const orderRes = await api.post('/orders', orderPayload);
      const orderId = orderRes.data.orderId || 'NEW';

                  // 2. Generate WhatsApp Message
      const itemsList = cartItems.map((item, index) => {
        const baseUrl = window.location.origin;
        const productIdentifier = item.slug || item.product_id || item.id;
        const productLink = baseUrl + '/product/' + productIdentifier; 
        const imgUrl = item.image.startsWith('http') ? item.image : baseUrl + '/view-image/' + btoa(item.image);
        
        let itemStr = '*' + item.quantity + 'x ' + item.name + '*\n';
        if (item.flavour) itemStr += 'Flavor: ' + item.flavour + '\n';
        itemStr += 'Price: ₹' + (item.price * item.quantity).toLocaleString('en-IN') + '\n';
        itemStr += '[View Product] - ' + productLink + '\n';
        itemStr += '[View Image] - ' + imgUrl;
        return itemStr;
      }).join('\n──────────────\n');

      let message = "";
      if (waSettings && waSettings.custom_template && waSettings.custom_template.trim()) {
        message = waSettings.custom_template
          .replace(/\[CUSTOMER_NAME\]/g, formData.name)
          .replace(/\[ORDER_ID\]/g, orderId)
          .replace(/\[ITEMS\]/g, itemsList)
          .replace(/\[TOTAL\]/g, cartTotal.toLocaleString('en-IN'));
      } else {
        message = `━━━━━━━━━━━━━━━━━━━━
🛍️ *VAPES Indiranagar | ORDER CONFIRMATION*
━━━━━━━━━━━━━━━━━━━━

*Order ID:* #${orderId}
*Status:* New Order Received

*CUSTOMER DETAILS*
👤 *Name:* ${formData.name}
📱 *Phone:* ${formData.phone}
📍 *Address:* ${formData.address}
📌 *PIN:* ${formData.pin_code}`;

        if (location) {
          message += `\n🗺️ *Map:* https://maps.google.com/?q=${location.lat},${location.lng}`;
        }

        message += `

*ORDER SUMMARY*
──────────────
${itemsList}
──────────────

*BILLING DETAILS*
Subtotal: ₹${cartTotal}
━━━━━━━━━━━━━━━━━━━━
*TOTAL DUE: ₹${cartTotal}*
━━━━━━━━━━━━━━━━━━━━`;
      }

      // 3. Clear cart and show success screen
      setWaRedirectUrl('https://wa.me/' + waSettings.business_number + '?text=' + encodeURIComponent(message));
      setOrderIdDisplay(orderId);
      setOrderSuccess(true);
      clearCart();
    } catch (error) {
      toast.error(error.response?.data?.error || "Failed to place order. Try again.");
      setIsSubmitting(false);
    }
  };

  if (orderSuccess) {
    return (
      <div className="checkout-page">
        <div className="container">
          <div className="order-success-container" style={{ textAlign: 'center', padding: '60px 20px', backgroundColor: 'var(--bg-surface)', borderRadius: '16px', border: '1px solid var(--border-color)', maxWidth: '600px', margin: '40px auto' }}>
            <div style={{ width: '80px', height: '80px', backgroundColor: 'rgba(37, 211, 102, 0.1)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px', color: '#25D366', fontSize: '40px' }}>
              <i className="fas fa-check-circle"></i>
            </div>
            <h1 style={{ color: 'var(--white)', marginBottom: '16px' }}>Order Placed Successfully!</h1>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '8px', fontSize: '16px' }}>Your Order ID is: <strong style={{ color: 'var(--primary-accent)' }}>#{orderIdDisplay}</strong></p>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '16px', fontSize: '16px', lineHeight: '1.6' }}>
              To complete your order and arrange for delivery, please send your order details to us on WhatsApp.
            </p>
            
            <div style={{ backgroundColor: 'rgba(255, 193, 7, 0.1)', border: '1px solid rgba(255, 193, 7, 0.3)', padding: '16px', borderRadius: '8px', marginBottom: '32px', textAlign: 'left' }}>
              <p style={{ color: '#ffc107', margin: 0, fontSize: '15px', lineHeight: '1.5' }}>
                <i className="fas fa-exclamation-triangle" style={{ marginRight: '8px' }}></i>
                <strong>Important:</strong> Your order is not finalized until you share these details with us on WhatsApp. Please click the button below to complete your order placement.
              </p>
            </div>
            
            <a href={waRedirectUrl} target="_blank" rel="noopener noreferrer" className="btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: '10px', fontSize: '18px', padding: '16px 32px', backgroundColor: '#25D366', color: '#fff', textDecoration: 'none', borderRadius: '30px', fontWeight: '600' }} onClick={() => {
              // Redirect to home after clicking WA
              setTimeout(() => {
                navigate.push('/');
              }, 1000);
            }}>
              <i className="fab fa-whatsapp" style={{ fontSize: '24px' }}></i> Continue to WhatsApp
            </a>
            
            <div style={{ marginTop: '24px' }}>
              <button onClick={() => navigate.push('/')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', textDecoration: 'underline', cursor: 'pointer', fontSize: '14px' }}>
                Return to Homepage
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="checkout-page">
      <div className="container">
        <div className="checkout-grid">
          
          <div className="checkout-form-col">
            <h2>Checkout Details</h2>
            <div className="card">
              <form onSubmit={handlePlaceOrder}>
                <div className="form-group">
                  <label>Full Name *</label>
                  <input type="text" name="name" value={formData.name} onChange={handleInputChange} placeholder="e.g. John Doe" required />
                </div>
                
                <div className="form-group">
                  <label>WhatsApp Number *</label>
                  <input type="tel" name="phone" value={formData.phone} onChange={handleInputChange} placeholder="10 digit number (without +91)" maxLength="10" pattern="[0-9]{10}" title="Please enter exactly 10 digits" required />
                </div>
                
                <div className="form-group full-width">
                  <label>Delivery Method</label>
                  <div className="delivery-options">
                    <button type="button" className={`delivery-opt-btn ${addressMethod === 'manual' ? 'active' : ''}`} onClick={() => setAddressMethod('manual')}>
                      <i className="fas fa-edit"></i> Enter Manually
                    </button>
                    <button type="button" className={`delivery-opt-btn ${addressMethod === 'fetch' ? 'active' : ''}`} onClick={() => { setAddressMethod('fetch'); handleGetLocation(); }}>
                      <i className="fas fa-map-marker-alt"></i> Fetch Location
                    </button>
                  </div>
                </div>

                {addressMethod === 'manual' && (
                  <>
                    <div className="form-group full-width">
                      <label>Delivery Address *</label>
                      <textarea name="address" value={formData.address} onChange={handleInputChange} placeholder="House/Flat No, Building, Street, Area..." rows="3" required={addressMethod === 'manual'}></textarea>
                    </div>
                    
                    <div className="form-group">
                      <label>PIN Code *</label>
                      <input type="text" name="pin_code" value={formData.pin_code} onChange={handlePinChange} placeholder="e.g. 560001" maxLength="6" required={addressMethod === 'manual'} />
                      {pinInfo && (
                        <div className="pin-info">
                          <i className={`fas ${pinInfo.includes('Invalid') ? 'fa-times-circle text-danger' : 'fa-check-circle text-success'}`}></i> 
                          <span>{pinInfo}</span>
                        </div>
                      )}
                      {isFetchingPin && <div className="pin-info"><i className="fas fa-spinner fa-spin"></i> Scanning PIN...</div>}
                    </div>
                  </>
                )}

                {addressMethod === 'fetch' && (
                  <div className="form-group full-width">
                    <label>Precise Location *</label>
                    <div className="location-action-row">
                      <button type="button" className={`fetch-loc-btn ${location ? 'location-active' : ''}`} onClick={handleGetLocation} disabled={isFetchingLocation}>
                        {isFetchingLocation ? (
                          <><i className="fas fa-spinner fa-spin"></i> Fetching Location...</>
                        ) : (
                          <><i className="fas fa-map-marker-alt"></i> {location ? 'Location Captured ✓' : 'Click to Fetch Current Location'}</>
                        )}
                      </button>
                    </div>
                    {location && !isFetchingLocation && (
                      <div className="location-display">
                        <i className="fas fa-check-circle text-success"></i> 
                        <span>{location.address}</span>
                      </div>
                    )}
                  </div>
                )}

                <button type="submit" className="btn-primary place-order-btn" disabled={isSubmitting}>
                  {isSubmitting ? 'Processing...' : 'Place Order via WhatsApp'} <i className="fab fa-whatsapp"></i>
                </button>
              </form>
            </div>
          </div>

          <div className="checkout-summary-col">
            <h2>Order Summary</h2>
            <div className="card summary-card">
              <div className="summary-items">
                {cartItems.map((item, index) => (
                  <div className="summary-item" key={index}>
                    <div className="summary-item-img">
                      <img loading="lazy" src={`${item.image}`} alt={item.name} onError={(e) => {e.target.src = '/placeholder.png'}} />
                    </div>
                                        <div className="summary-item-info">
                      <Link href={`/product/${item.slug || item.product_id || item.id}`} style={{ textDecoration: 'none', color: 'inherit' }}>
                        <h4 className="hover-accent">{item.name}</h4>
                      </Link>
                      {item.flavour && <p>Flavour: {item.flavour}</p>}
                      <div className="summary-item-actions">
                        <div className="minimal-qty">
                          <button type="button" disabled={item.quantity <= 1} onClick={() => updateQuantity(item.product_id || item.id, item.flavour, item.quantity - 1)}>-</button>
                          <span>{item.quantity}</span>
                          <button type="button" onClick={() => updateQuantity(item.product_id || item.id, item.flavour, item.quantity + 1)}>+</button>
                        </div>
                        <button type="button" className="minimal-delete" onClick={() => removeFromCart(item.product_id || item.id, item.flavour)} title="Remove item">
                          <i className="fas fa-trash-alt"></i>
                        </button>
                      </div>
                    </div>
                                        <div className="summary-item-price">
                      ₹{(item.price * item.quantity).toLocaleString('en-IN')}
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="summary-total">
                <span>Total Amount:</span>
                <span className="total-price">₹{cartTotal}</span>
              </div>
              </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Checkout;

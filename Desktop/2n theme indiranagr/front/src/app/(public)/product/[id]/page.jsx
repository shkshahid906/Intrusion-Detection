"use client";

import React, { useState, useEffect, useContext, Suspense } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import api from '../../../../services/api';
import { CartContext } from '../../../../context/CartContext';
import { FiShoppingBag, FiCreditCard, FiDroplet } from 'react-icons/fi';
import { toast } from 'react-toastify';
import { Swiper, SwiperSlide } from 'swiper/react';
import { Navigation, Thumbs, Autoplay, FreeMode } from 'swiper/modules';
import { Helmet } from 'react-helmet-async';
import 'swiper/css';
import 'swiper/css/navigation';
import 'swiper/css/thumbs';
import './ProductDetails.css';
import ProductsGrid from '../../../../components/public/ProductsGrid'; // For related products

const ProductDetails = () => {
  const { id } = useParams();
  const navigate = useRouter();
  const [product, setProduct] = useState(null);
  const [loading, setLoading] = useState(true);
  const [thumbsSwiper, setThumbsSwiper] = useState(null);
  const [mainSwiper, setMainSwiper] = useState(null);
  
  const [selectedFlavour, setSelectedFlavour] = useState('');
  const [quantity, setQuantity] = useState(1);
  const [isDescExpanded, setIsDescExpanded] = useState(false);

  const { addToCart, setIsCartOpen } = useContext(CartContext);

  useEffect(() => {
    const fetchProduct = async () => {
      try {
        setLoading(true);
        let actualId = id;
        try {
          if (isNaN(id)) {
            actualId = atob(decodeURIComponent(id));
          }
        } catch (e) {}
        const res = await api.get('/products/' + actualId);
        if (res.data.success) {
          setProduct(res.data.product);
        }
      } catch (err) {
        toast.error('Failed to load product details');
        navigate.push('/');
      } finally {
        setLoading(false);
      }
    };
    fetchProduct();
    window.scrollTo(0, 0);
  }, [id, navigate]);

  const handleAdd = () => {
    if (product.flavours && product.flavours.length > 0 && !selectedFlavour) {
      toast.warning("Please select a flavour first");
      return;
    }
    const res = addToCart(product, quantity, selectedFlavour);
    if (res && res.success === false) {
      toast.warning(res.message);
    } else {
      toast.success(`${product.name} added to cart`);
      setIsCartOpen(true);
    }
  };

  const handleBuyNow = () => {
    if (product.flavours && product.flavours.length > 0 && !selectedFlavour) {
      toast.warning("Please select a flavour first");
      return;
    }
    const res = addToCart(product, quantity, selectedFlavour);
    if (res && res.success === false) {
      toast.warning(res.message);
    } else {
      setIsCartOpen(false); // Do not open cart drawer
      navigate.push('/checkout'); // Go straight to checkout
    }
  };

  const flavours = product?.flavours || [];

  // Calculate current max stock
  let maxStock = product?.stock || 0;
  if (flavours.length > 0) {
    if (selectedFlavour) {
      const fObj = flavours.find(f => f.flavour_name === selectedFlavour);
      maxStock = fObj ? fObj.stock : 0;
    } else {
      maxStock = 0; // Default to 0 until a flavour is selected
    }
  }

  // Effect to ensure quantity doesn't exceed maxStock when flavour changes
  useEffect(() => {
    if (maxStock > 0 && quantity > maxStock) {
      setQuantity(maxStock);
    }
  }, [maxStock, quantity]);

  const isOutOfStock = maxStock <= 0;

  if (loading) return <div className="loading-spinner">Loading product...</div>;
  if (!product) return <div className="loading-spinner">Product not found.</div>;

  const images = product.images && product.images.length > 0 
    ? product.images.map(img => img.image_path)
    : (product.primary_image ? [product.primary_image] : ['/placeholder.png']);

  const getCleanDescription = () => {
    let rawText = '';
    if (product.short_description) {
      rawText = product.short_description;
    } else if (product.description) {
      // Strip HTML tags using regex if DOMParser is unavailable during SSR
      rawText = product.description.replace(/<[^>]*>?/gm, ' ').trim();
    }
    return rawText.length > 160 ? rawText.substring(0, 157) + '...' : rawText;
  };

  return (
    <div className="product-details-page">
      <Helmet>
        <title>{product.name}</title>
        <meta name="description" content={getCleanDescription()} />
        {/* Open Graph Tags for social sharing */}
        <meta property="og:title" content={product.name} />
        <meta property="og:description" content={getCleanDescription()} />
        <meta property="og:image" content={images[0]} />
        <meta property="og:image:alt" content={getCleanDescription()} />
      </Helmet>

      <div className="container">
        
        {/* Breadcrumb */}
        <div className="breadcrumb" style={{ marginBottom: '10px', fontSize: '14px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', zIndex: 10, position: 'relative', flexWrap: 'nowrap' }}>
          <Link href="/" style={{ color: 'var(--primary-accent)', textDecoration: 'none', transition: 'color 0.2s', whiteSpace: 'nowrap', flexShrink: 0 }}>Home</Link>
          <span style={{ margin: '0 10px', opacity: 0.5, flexShrink: 0 }}>/</span>
          <Link href="/#products" style={{ color: 'var(--primary-accent)', textDecoration: 'none', transition: 'color 0.2s', whiteSpace: 'nowrap', flexShrink: 0 }}>Products</Link>
          <span style={{ margin: '0 10px', opacity: 0.5, flexShrink: 0 }}>/</span>
          <span style={{ color: 'var(--white)', fontWeight: '600', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flex: 1, minWidth: 0 }}>{product.name}</span>
        </div>

        <div className="product-details-grid">
          
          {/* Left: Gallery */}
          <div className="product-gallery">
            <Swiper
              onSwiper={setMainSwiper}
              style={{
                '--swiper-navigation-color': 'var(--primary-accent)',
                '--swiper-pagination-color': 'var(--primary-accent)',
              }}
              loop={images.length > 1}
              spaceBetween={10}
              navigation={true}
              autoplay={{ delay: 3000, disableOnInteraction: false }}
              thumbs={{ swiper: thumbsSwiper && !thumbsSwiper.destroyed ? thumbsSwiper : null }}
              modules={[Navigation, Thumbs, Autoplay]}
              className="main-swiper"
            >
              {images.map((img, i) => (
                <SwiperSlide key={i}>
                  <div className="main-image-wrapper">
                    <img loading="lazy" src={`${img}`} alt={`${product.name} - ${getCleanDescription()}`} onError={(e) => { e.currentTarget.onerror = null; e.currentTarget.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 400 400"><rect width="400" height="400" fill="%23f1f5f9"/><text x="200" y="200" font-family="sans-serif" font-size="24" fill="%2394a3b8" text-anchor="middle" dominant-baseline="middle">No Image</text></svg>'; }} />
                  </div>
                </SwiperSlide>
              ))}
            </Swiper>
            
            {images.length > 1 && (
              <Swiper
                onSwiper={setThumbsSwiper}
                loop={false}
                spaceBetween={6}
                slidesPerView={4.5}
                freeMode={true}
                watchSlidesProgress={true}
                slideToClickedSlide={true}
                modules={[Navigation, Thumbs, FreeMode]}
                className="thumb-swiper"
              >
                {images.map((img, i) => (
                  <SwiperSlide key={i} onClick={() => mainSwiper && mainSwiper.slideToLoop(i)}>
                    <div className="thumb-image-wrapper">
                      <img loading="lazy" src={`${img}`} alt={`${product.name} thumbnail`} onError={(e) => { e.currentTarget.onerror = null; e.currentTarget.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 400 400"><rect width="400" height="400" fill="%23f1f5f9"/><text x="200" y="200" font-family="sans-serif" font-size="24" fill="%2394a3b8" text-anchor="middle" dominant-baseline="middle">No Image</text></svg>'; }} />
                    </div>
                  </SwiperSlide>
                ))}
              </Swiper>
            )}
          </div>

          {/* Right: Details */}
          <div className="product-info-panel">
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px' }}>
              <div className="category-badge">{product.category_name}</div>
              {product.nicotine_strength && (
                <div className="mg-pill" style={{ position: 'static', display: 'inline-flex' }}>
                  <FiDroplet size={12} className="mg-icon" /> {product.nicotine_strength}
                </div>
              )}
            </div>
            <h1>{product.name}</h1>
            
            <div className="price-row">
              <span className="price">₹{product.price}</span>
              {product.mrp > product.price && <span className="mrp">₹{product.mrp}</span>}
              {product.mrp > product.price && (
                <span className="discount-badge">
                  {Math.round(((product.mrp - product.price) / product.mrp) * 100)}% OFF
                </span>
              )}
            </div>

            {product.short_description && (
              <div className="product-short-description" style={{ color: 'var(--text-secondary)', marginBottom: '24px', fontSize: '14px', lineHeight: '1.6' }}>
                {product.short_description}
              </div>
            )}

            {flavours.length > 0 && (
              <div className="selection-group">
                <h3>Select Flavour</h3>
                <div className="flavour-options">
                  {flavours.map(f => (
                    <button 
                      key={f.id}
                      className={`flavour-btn ${selectedFlavour === f.flavour_name ? 'selected' : ''} ${f.stock <= 0 ? 'out-of-stock' : ''}`}
                      onClick={() => f.stock > 0 && setSelectedFlavour(f.flavour_name)}
                      disabled={f.stock <= 0}
                    >
                      {f.flavour_name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="selection-group">
              <h3>Quantity</h3>
              <div className="qty-selector">
                <button onClick={() => setQuantity(q => Math.max(1, q - 1))} disabled={isOutOfStock}>-</button>
                <span>{quantity}</span>
                <button onClick={() => setQuantity(q => Math.min(maxStock, q + 1))} disabled={isOutOfStock || quantity >= maxStock}>+</button>
              </div>
            </div>

            <div className="action-buttons">
              {isOutOfStock && (!flavours.length || selectedFlavour) ? (
                 <button className="btn-outline add-cart" disabled style={{ opacity: 0.5, cursor: 'not-allowed', width: '100%' }}>
                   Out of Stock
                 </button>
              ) : (
                <>
                  <button className="btn-outline add-cart" onClick={handleAdd}>
                    <FiShoppingBag style={{marginRight: '8px'}} /> Add to Cart
                  </button>
                  <button className="btn-primary buy-now" onClick={handleBuyNow}>
                    <FiCreditCard style={{marginRight: '8px'}} /> Buy It Now
                  </button>
                </>
              )}
            </div>
            
            <div className="delivery-info">
              <div className="info-item">
                <i className="fas fa-truck"></i> Fast Delivery across Indiranagar
              </div>
              <div className="info-item">
                <i className="fab fa-whatsapp"></i> Order tracking via WhatsApp
              </div>
            </div>

            {product.description && (
              <div className="product-long-description" style={{ marginTop: '40px', paddingTop: '40px', borderTop: '1px solid var(--border-color)' }}>
                <h3 style={{ marginBottom: '20px', fontSize: '18px', color: 'var(--white)' }}>Product Details</h3>
                <div 
                  className={`product-description ${!isDescExpanded && product.description.length > 400 ? 'collapsed' : 'expanded'}`}
                >
                  <div dangerouslySetInnerHTML={{ __html: product.description }}></div>
                </div>
                {product.description.length > 400 && (
                  <button 
                    className="read-more-btn" 
                    onClick={() => setIsDescExpanded(!isDescExpanded)}
                  >
                    {isDescExpanded ? 'Show Less' : 'Read More'}
                  </button>
                )}
              </div>
            )}

          </div>
        </div>

        {/* Related Products Placeholder */}
        <div className="related-products">
          <div className="section-header center">
            <h2>You May Also Like</h2>
          </div>
          {/* For now, just render the ProductsGrid which fetches all. In future, we can pass a categoryId prop to filter. */}
          <Suspense fallback={<div>Loading related products...</div>}>
            <ProductsGrid />
          </Suspense>
        </div>

      </div>
    </div>
  );
};

export default ProductDetails;

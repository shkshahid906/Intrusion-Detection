import React from 'react';
import Link from 'next/link';
import { FiDroplet } from 'react-icons/fi';
import { FaWhatsapp } from 'react-icons/fa';

const ProductCard = ({ product, index, onAdd }) => {
  const image = product.primary_image || (product.images && product.images.length > 0 ? product.images[0].image_path : '/placeholder.png');
  const discount = product.mrp > product.price ? Math.round(((product.mrp - product.price) / product.mrp) * 100) : 0;
  
  // Tag above title: Use actual category name provided by Admin
  let tag = product.category_name ? product.category_name.toUpperCase() : 'PRODUCT';
  let tagClass = 'new'; // default
  
  if (tag.includes('TOBACCO')) tagClass = 'tobacco';
  else if (tag.includes('LIQUID') || tag.includes('JUICE')) tagClass = 'fast';
  
  // Tag over image: Use short_description if provided by Admin (e.g., '10,000 Puffs' or '50g')
  let imageTag = null;
  if (product.short_description && product.short_description.length <= 20) {
    imageTag = product.short_description;
  }

  return (
    <>
      {/* Desktop Product Card */}
      <div className="product-card product-card-desktop">
        <Link href={`/product/${product.slug || product.id}`} className="product-image-link">
          
          {/* Top Badges Bar */}
          <div className="card-badges-top">
            {discount > 0 ? <div className="discount-pill">{discount}% OFF</div> : <div></div>}
            
            {product.nicotine_strength && (
              <div className="mg-pill">
                <FiDroplet size={11} className="mg-icon" /> {product.nicotine_strength}
              </div>
            )}
          </div>

          <div className="product-image-wrapper">
            <img loading="lazy" src={`${image}`} alt={product.name || 'Product'} onError={(e) => { e.currentTarget.onerror = null; e.currentTarget.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 400 400"><rect width="400" height="400" fill="%23f1f5f9"/><text x="200" y="200" font-family="sans-serif" font-size="24" fill="%2394a3b8" text-anchor="middle" dominant-baseline="middle">No Image</text></svg>'; }} />
          </div>
          {imageTag && <div className="image-tag-pill">{imageTag}</div>}
        </Link>
        
        <div className="product-info">
          <div className={`tag-outline ${tagClass}`}>{tag}</div>
          
          <Link href={`/product/${product.slug || product.id}`} className="product-title-link">
            <h3>{product.name || 'Unnamed Product'}</h3>
          </Link>
          
          <div className="product-price-row">
            <span className="price">₹{product.price}</span>
            {product.mrp > product.price && <span className="mrp">₹{product.mrp}</span>}
          </div>

          {product.flavours && product.flavours.length > 0 ? (
             <Link href={`/product/${product.slug || product.id}`} className="btn-add-cart">
              <FiDroplet /> Select Flavour
            </Link>
          ) : product.stock <= 0 ? (
            <button className="btn-add-cart" disabled style={{ opacity: 0.5, cursor: 'not-allowed' }}>
              Out of Stock
            </button>
          ) : (
            <button onClick={(e) => {
              e.preventDefault();
              if(onAdd) onAdd(product);
            }} className="btn-add-cart">
              <FaWhatsapp /> Order on WhatsApp
            </button>
          )}
        </div>
      </div>

      {/* Mobile Product Card */}
      <div className="best-selling-minimal-card product-card-mobile">
        <Link href={`/product/${product.slug || product.id}`} className="best-selling-img-box">
          
          {/* Top Badges Bar */}
          <div className="card-badges-top">
            {discount > 0 ? <div className="discount-pill">{discount}% OFF</div> : <div></div>}
            
            {product.nicotine_strength && (
              <div className="mg-pill">
                <FiDroplet className="mg-icon" /> {product.nicotine_strength}
              </div>
            )}
          </div>

          <img loading="lazy" src={`${image}`} alt={product.name || 'Product'} onError={(e) => { e.currentTarget.onerror = null; e.currentTarget.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 400 400"><rect width="400" height="400" fill="%23f1f5f9"/><text x="200" y="200" font-family="sans-serif" font-size="24" fill="%2394a3b8" text-anchor="middle" dominant-baseline="middle">No Image</text></svg>'; }} />
        </Link>
        
        <div className="marquee-product-info">
          <Link href={`/product/${product.slug || product.id}`} style={{textDecoration: 'none', width: '100%'}}>
            <p className="marquee-product-name">{product.name || 'Unnamed Product'}</p>
          </Link>
          
          <div className="product-price-row" style={{justifyContent: 'flex-start', margin: 0, gap: '6px', width: '100%', alignItems: 'center', flexWrap: 'wrap'}}>
            <span className="marquee-product-price">₹{parseFloat(product.price)}</span>
            {product.mrp > product.price && <span className="mrp" style={{fontSize: '10px', textDecoration: 'line-through', color: 'var(--text-secondary)'}}>₹{parseFloat(product.mrp)}</span>}
          </div>

          {product.flavours && product.flavours.length > 0 ? (
             <Link href={`/product/${product.slug || product.id}`} className="marquee-add-btn">
              <FiDroplet size={14} /> Select
            </Link>
          ) : product.stock <= 0 ? (
            <button className="marquee-add-btn disabled" disabled>
              Sold Out
            </button>
          ) : (
            <button onClick={(e) => {
              e.preventDefault();
              if(onAdd) onAdd(product);
            }} className="marquee-add-btn">
              <FaWhatsapp size={14} /> Order
            </button>
          )}
        </div>
      </div>
    </>
  );
};

export default ProductCard;

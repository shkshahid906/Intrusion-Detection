"use client";

import React, { useState, useEffect, useContext, useRef } from 'react';
import Link from 'next/link';
import { useRouter, usePathname, useSearchParams } from 'next/navigation';
import { CartContext } from '../../context/CartContext';
import api from '../../services/api';
import { FiShoppingBag, FiSearch, FiHome, FiGrid, FiInfo, FiPhone, FiLayers } from 'react-icons/fi';
import logoImg from '../../assets/v_h_logo.jpeg';
import './Header.css';

const Header = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isMobileSearchOpen, setIsMobileSearchOpen] = useState(false);
  const [whatsappNumber, setWhatsappNumber] = useState('');
  const [defaultMsg, setDefaultMsg] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [products, setProducts] = useState([]);
  const [categories, setCategories] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isMobileCategoriesOpen, setIsMobileCategoriesOpen] = useState(false);
  const [logoSrc, setLogoSrc] = useState(logoImg.src);
  
  const { cartItems, isCartOpen, setIsCartOpen } = useContext(CartContext) || { cartItems: [] };
  const cartCount = cartItems.reduce((acc, item) => acc + item.quantity, 0);
  const navigate = useRouter();
  const location = usePathname();
  const searchParams = useSearchParams();
  const searchContainerRef = useRef(null);
  const mobileSearchInputRef = useRef(null);

  useEffect(() => {
    if (isMobileSearchOpen && mobileSearchInputRef.current) {
      setTimeout(() => {
        mobileSearchInputRef.current.focus();
      }, 100);
    }
  }, [isMobileSearchOpen]);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };
    window.addEventListener('scroll', handleScroll);
    
    // Fetch WhatsApp Settings for CTA
    const fetchWa = async () => {
      try {
        const res = await api.get('/cms/whatsapp');
        if (res.data.success && res.data.whatsapp) {
          setWhatsappNumber(res.data.whatsapp.business_number);
          setDefaultMsg(res.data.whatsapp.default_message);
        }
      } catch (err) {
        console.error("Failed to load WA info", err);
      }
    };
    
    const fetchProducts = async () => {
      try {
        const res = await api.get('/products');
        if (res.data.success && res.data.products) {
          setProducts(res.data.products.filter(p => p.status === 1 || p.status === 'active'));
        }
      } catch (err) {
        console.error("Failed to load products for search", err);
      }
    };

    const fetchCategories = async () => {
      try {
        const res = await api.get('/categories');
        if (res.data.success && res.data.categories) {
          setCategories(res.data.categories.filter(c => c.status === 1 || c.status === 'active'));
        }
      } catch (err) {
        console.error("Failed to load categories", err);
      }
    };

    const fetchContactInfo = async () => {
      try {
        const res = await api.get('/cms/contact-info');
        if (res.data.success && res.data.contactInfo) {
          if (res.data.contactInfo.logo_image) {
            setLogoSrc(res.data.contactInfo.logo_image);
          }
        }
      } catch (err) {
        console.error("Failed to load contact info", err);
      }
    };

    fetchWa();
    fetchProducts();
    fetchCategories();
    fetchContactInfo();
    
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Sync search input with URL if it's cleared from elsewhere
  useEffect(() => {
    const query = searchParams ? searchParams.get('search') : null;
    if (!query) {
      setSearchQuery('');
    }
  }, [searchParams]);
  
  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (searchContainerRef.current && !searchContainerRef.current.contains(event.target)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const waLink = whatsappNumber ? `https://wa.me/${whatsappNumber}?text=${encodeURIComponent(defaultMsg || 'Hello!')}` : '#';

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate.push(`/?search=${encodeURIComponent(searchQuery.trim())}#products`, { scroll: false });
    } else {
      navigate.push(`/#products`, { scroll: false }); // Clear the search from URL
    }
    setShowSuggestions(false);
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
  };
  
  const handleSuggestionClick = (productId) => {
    navigate.push(`/product/${productId}`);
    setShowSuggestions(false);
    setSearchQuery('');
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
  };

  const handleCategorySuggestionClick = (catTarget) => {
    navigate.push(`/?category=${catTarget}#products`);
    setShowSuggestions(false);
    setSearchQuery('');
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
  };

  const filteredCategorySuggestions = searchQuery.trim() === '' ? [] : categories.filter(c => 
    (c.category_name || '').toLowerCase().includes(searchQuery.trim().toLowerCase())
  ).slice(0, 3);

  const filteredSuggestions = searchQuery.trim() === '' ? [] : products.filter(p => {
    const searchLower = searchQuery.trim().toLowerCase();
    const nameStr = (p.name || '').toLowerCase();
    const catStr = (p.category_name || '').toLowerCase();
    const shortDescStr = (p.short_description || '').toLowerCase();
    
    // Check matching flavour
    const matchedFlavourObj = Array.isArray(p.flavours) ? p.flavours.find(f => 
      (f.flavour_name || '').toLowerCase().includes(searchLower)
    ) : null;

    p.matchingFlavour = matchedFlavourObj ? matchedFlavourObj.flavour_name : null;

    return nameStr.includes(searchLower) || 
           catStr.includes(searchLower) || 
           shortDescStr.includes(searchLower) || 
           !!matchedFlavourObj;
  }).slice(0, 5); // Limit to 5 suggestions

  return (
    <>
      <header className={`public-header ${isScrolled ? 'scrolled' : ''}`}>
        <div className="container header-container">
          <Link href="/" className="logo" style={{ display: 'flex', alignItems: 'center', textDecoration: 'none' }}>
            <img src={logoSrc} alt="Logo" style={{ height: '50px', width: 'auto', objectFit: 'contain', borderRadius: '4px' }} />
          </Link>
          
          <nav className="desktop-nav">
            <Link href="/" className="nav-link" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>Home</Link>
            <div className="nav-dropdown-container">
              <span className="nav-link">Categories <i className="fas fa-chevron-down" style={{fontSize: '10px', marginLeft: '4px'}}></i></span>
              <div className="nav-dropdown-menu">
                <Link href="/#products" className="dropdown-item">All Categories</Link>
                {categories.map(c => (
                  <Link key={c.id} href={`/?category=${c.id}#products`} className="dropdown-item">{c.category_name}</Link>
                ))}
              </div>
            </div>
            <Link href="/#products" className="nav-link">Shop</Link>
            <Link href="/#about" className="nav-link">About</Link>
            <Link href="/#contact" className="nav-link">Contact</Link>
          </nav>
          
          <div className="header-right">
            <div className="search-container desktop-search" ref={searchContainerRef}>
              <form className="search-bar" onSubmit={handleSearch}>
                <FiSearch className="search-icon" />
                <input 
                  type="text" 
                  placeholder="Search products..." 
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setShowSuggestions(true);
                  }}
                  onFocus={() => setShowSuggestions(true)}
                />
              </form>
              
              {/* Desktop Suggestions Dropdown */}
              {showSuggestions && (filteredSuggestions.length > 0 || filteredCategorySuggestions.length > 0) && (
                <div className="search-suggestions">
                  {filteredCategorySuggestions.map(cat => (
                    <div 
                      key={`cat-${cat.id}`} 
                      className="suggestion-item suggestion-category-item"
                      style={{ background: 'rgba(0, 184, 255, 0.08)', borderBottom: '1px solid var(--border-color)', padding: '10px 14px' }}
                      onMouseDown={(e) => { e.preventDefault(); handleCategorySuggestionClick(cat.slug || cat.id); }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary-accent)', fontSize: '13px', fontWeight: '600' }}>
                        <FiLayers size={14} /> Category: <span style={{ color: 'var(--white)' }}>{cat.category_name}</span>
                      </div>
                    </div>
                  ))}
                  {filteredSuggestions.map(product => (
                    <div 
                      key={product.id} 
                      className="suggestion-item"
                      onMouseDown={(e) => { e.preventDefault(); handleSuggestionClick(product.slug || product.id); }}
                    >
                      <div className="suggestion-img">
                        <img loading="lazy" src={`${product.primary_image || (product.images?.[0]?.image_path) || '/placeholder.png'}`} alt={product.name} />
                      </div>
                      <div className="suggestion-details">
                        <h4>{product.name}</h4>
                        {product.matchingFlavour && (
                          <span style={{ fontSize: '11px', color: '#E8B437', display: 'block', marginBottom: '2px', fontWeight: '500' }}>
                            Flavour: {product.matchingFlavour}
                          </span>
                        )}
                        <span>₹{product.price}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <button className="nav-btn mobile-search-toggle" onClick={() => {
              setIsMobileSearchOpen(!isMobileSearchOpen);
              if (!isMobileSearchOpen) setIsMobileMenuOpen(false);
            }} title="Search">
              <FiSearch />
            </button>

            <button className="nav-btn cart-btn" onClick={() => setIsCartOpen(true)} title="Cart">
              <FiShoppingBag /> {cartCount > 0 && <span className="cart-badge">{cartCount}</span>}
            </button>
            
            <button className={`mobile-toggle ${isMobileMenuOpen ? 'open' : ''}`} onClick={() => {
              setIsMobileMenuOpen(!isMobileMenuOpen);
              if (!isMobileMenuOpen) setIsMobileSearchOpen(false);
            }} aria-label="Menu">
              <span></span>
              <span></span>
              <span></span>
            </button>
          </div>
        </div>

        {/* Mobile Search Dropdown */}
        <div className={`mobile-search-dropdown ${isMobileSearchOpen ? 'open' : ''}`}>
          <div className="container">
            <form className="search-bar" onSubmit={handleSearch}>
              <FiSearch className="search-icon" />
              <input 
                ref={mobileSearchInputRef}
                type="text" 
                placeholder="Search products..." 
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setShowSuggestions(true);
                }}
              />
            </form>
            {showSuggestions && (filteredSuggestions.length > 0 || filteredCategorySuggestions.length > 0) && (
              <div className="search-suggestions-mobile">
                {filteredCategorySuggestions.map(cat => (
                  <div 
                    key={`cat-${cat.id}`} 
                    className="suggestion-item suggestion-category-item"
                    style={{ background: 'rgba(0, 184, 255, 0.08)', borderBottom: '1px solid var(--border-color)', padding: '10px 14px' }}
                    onMouseDown={(e) => { e.preventDefault(); handleCategorySuggestionClick(cat.slug || cat.id); }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary-accent)', fontSize: '13px', fontWeight: '600' }}>
                      <FiLayers size={14} /> Category: <span style={{ color: 'var(--white)' }}>{cat.category_name}</span>
                    </div>
                  </div>
                ))}
                {filteredSuggestions.map(product => (
                  <div 
                    key={product.id} 
                    className="suggestion-item"
                    onMouseDown={(e) => { e.preventDefault(); handleSuggestionClick(product.slug || product.id); }}
                  >
                    <div className="suggestion-img">
                      <img loading="lazy" src={`${product.primary_image || (product.images?.[0]?.image_path) || '/placeholder.png'}`} alt={product.name} />
                    </div>
                    <div className="suggestion-details">
                      <h4>{product.name}</h4>
                      {product.matchingFlavour && (
                        <span style={{ fontSize: '11px', color: '#E8B437', display: 'block', marginBottom: '2px', fontWeight: '500' }}>
                          Flavour: {product.matchingFlavour}
                        </span>
                      )}
                      <span>₹{product.price}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </header>
      
      {/* Mobile Navigation Overlay */}
      <div 
        className={`mobile-nav-backdrop ${isMobileMenuOpen ? 'open' : ''}`} 
        onClick={() => setIsMobileMenuOpen(false)}
      ></div>
      <div className={`mobile-nav ${isMobileMenuOpen ? 'open' : ''}`}>
        <Link href="/" className="mobile-nav-link" onClick={() => { setIsMobileMenuOpen(false); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>
          <FiHome /> <span>Home</span>
        </Link>
        <Link href="/#products" className="mobile-nav-link" onClick={() => setIsMobileMenuOpen(false)}>
          <FiGrid /> <span>Shop All</span>
        </Link>
        <div className="mobile-nav-categories-container">
          <button 
            className="mobile-nav-link" 
            style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'none', border: 'none', cursor: 'pointer' }}
            onClick={() => setIsMobileCategoriesOpen(!isMobileCategoriesOpen)}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
              <FiLayers /> <span>Categories</span>
            </div>
            <i className={`fas fa-chevron-${isMobileCategoriesOpen ? 'up' : 'down'}`} style={{ fontSize: '12px', color: 'var(--text-secondary)' }}></i>
          </button>
          
          <div className={`mobile-nav-categories-dropdown ${isMobileCategoriesOpen ? 'open' : ''}`}>
            <Link href="/#products" className="mobile-nav-sublink" onClick={() => { setIsMobileMenuOpen(false); setIsMobileCategoriesOpen(false); }}>
              - All Products
            </Link>
            {categories.map(c => (
              <Link key={c.id} href={`/?category=${c.id}#products`} className="mobile-nav-sublink" onClick={() => { setIsMobileMenuOpen(false); setIsMobileCategoriesOpen(false); }}>
                - {c.category_name}
              </Link>
            ))}
          </div>
        </div>
        <Link href="/#about" className="mobile-nav-link" onClick={() => setIsMobileMenuOpen(false)}>
          <FiInfo /> <span>About</span>
        </Link>
        <Link href="/#contact" className="mobile-nav-link" onClick={() => setIsMobileMenuOpen(false)}>
          <FiPhone /> <span>Contact</span>
        </Link>
      </div>
      
      {/* Floating WhatsApp Button */}
      {whatsappNumber && (
        <a href={waLink} target="_blank" rel="noreferrer" className="floating-wa">
          <i className="fab fa-whatsapp"></i>
        </a>
      )}
    </>
  );
};

export default Header;

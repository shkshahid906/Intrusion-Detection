"use client";

import React, { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import api from '../../services/api';
import { Swiper, SwiperSlide } from 'swiper/react';
import { Autoplay, Pagination, EffectFade } from 'swiper/modules';
import ProductsGrid from '../../components/public/ProductsGrid';
import BestSellingSection from '../../components/public/BestSellingSection';
import ContactSection from '../../components/public/ContactSection';
import DeliveryAreasSection from '../../components/public/DeliveryAreasSection';
import { CartContext } from '../../context/CartContext';
import { toast } from 'react-toastify';
import 'swiper/css';
import 'swiper/css/pagination';
import 'swiper/css/effect-fade';
import './Home.css';
import { FiCheckCircle, FiClock, FiShield, FiBox, FiShoppingBag, FiDroplet, FiArrowRight, FiTruck, FiStar } from 'react-icons/fi';
import { FaWhatsapp } from 'react-icons/fa';
import { LuShieldCheck, LuFlaskConical, LuTruck, LuBadgeCheck } from 'react-icons/lu';

const Home = () => {
  const [banners, setBanners] = useState([]);
  const [marqueeItems, setMarqueeItems] = useState([]);
  const [about, setAbout] = useState(null);
  const [whyChooseUs, setWhyChooseUs] = useState([]);
  const [whatsappNumber, setWhatsappNumber] = useState('');
  const [defaultMsg, setDefaultMsg] = useState('');
  const location = usePathname();
  
  const cartContext = React.useContext(CartContext);

  const handleAddToCart = (product, e) => {
    e.preventDefault();
    if (!cartContext) return;
    const res = cartContext.addToCart(product, 1);
    if (res && res.success === false) {
      toast.warning(res.message);
    } else {
      toast.success(`${product.name} added to cart`);
      cartContext.setIsCartOpen(true);
    }
  };

  // Scroll to hash when location changes
  useEffect(() => {
    if (location.hash) {
      const id = location.hash.replace('#', '');
      setTimeout(() => {
        const element = document.getElementById(id);
        if (element) {
          // Adjust scroll position to account for fixed header (approx 80px)
          const y = element.getBoundingClientRect().top + window.scrollY - 90;
          window.scrollTo({ top: y, behavior: 'smooth' });
        }
      }, 300);
    }
  }, [location]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const results = await Promise.allSettled([
          api.get('/banners'),
          api.get('/products'),
          api.get('/cms/about'),
          api.get('/cms/why-choose-us'),
          api.get('/cms/whatsapp')
        ]);
        
        const [bannerRes, prodRes, aboutRes, whyRes, waRes] = results;

        if (bannerRes.status === 'fulfilled' && bannerRes.value.data.success) {
          setBanners(bannerRes.value.data.banners.filter(b => b.status === 'active' || b.status === 1));
        }
        if (prodRes.status === 'fulfilled' && prodRes.value.data.success) {
          const items = prodRes.value.data.products || [];
          setMarqueeItems(items.filter(p => (p.status === 1 || p.status === 'active') && (p.featured === 1 || p.featured === 'yes')));
        }
        if (aboutRes.status === 'fulfilled' && aboutRes.value.data.success) {
          setAbout(aboutRes.value.data.about);
        }
        if (whyRes.status === 'fulfilled' && whyRes.value.data.success) {
          setWhyChooseUs(whyRes.value.data.items.filter(w => w.status === 'active' || w.status === 1));
        }
        if (waRes.status === 'fulfilled' && waRes.value.data.success && waRes.value.data.whatsapp) {
          setWhatsappNumber(waRes.value.data.whatsapp.business_number || '');
          setDefaultMsg(waRes.value.data.whatsapp.default_message || '');
        }
      } catch (err) {
        console.error("Error fetching homepage data", err);
      }
    };
    fetchData();
  }, []);

  const waLink = whatsappNumber ? `https://wa.me/${whatsappNumber}?text=${encodeURIComponent(defaultMsg || 'Hello!')}` : '#';

  return (
    <div className="home-page">
      
      {/* Redesigned Static Hero Section */}
      <section className="hero-section">
        <div className="container hero-container">
          <div className="hero-content">
            <h1>Elevate your vaping <span style={{ color: 'var(--primary-accent)' }}>experience.</span></h1>
            <p>Discover top-tier disposable vapes, premium e-liquids, and advanced pod systems. Authentic products, unmatched flavor profiles, and lightning-fast local delivery.</p>
            <div className="hero-buttons">
              <a href="#products" className="btn-primary">Shop the collection <i className="fas fa-chevron-right" style={{ marginLeft: '6px', fontSize: '12px' }}></i></a>
              <a href="#products" className="btn-outline">Browse e-liquids <i className="fas fa-chevron-right" style={{ marginLeft: '6px', fontSize: '12px' }}></i></a>
            </div>
            <div className="hero-guarantees">
              <div className="guarantee-item">
                <FiCheckCircle /> Age-verified checkout
              </div>
              <div className="guarantee-item">
                <FiBox /> Ships in 24 hours
              </div>
            </div>
          </div>
          <div className="hero-image-wrapper">
            <div className="hero-image-box">
               {banners.length > 0 ? (
                 <Swiper
                   modules={[Autoplay, Pagination, EffectFade]}
                   autoplay={{ delay: 3000, disableOnInteraction: false }}
                   pagination={{ clickable: true }}
                   effect="fade"
                   loop={true}
                   className="hero-swiper"
                 >
                   {banners.map((b, i) => (
                     <SwiperSlide key={i}>
                       <a href={waLink} target="_blank" rel="noopener noreferrer" style={{ display: 'block' }}>
                         <img src={`${b.image_path}`} alt="Premium Vape Banner" />
                       </a>
                     </SwiperSlide>
                   ))}
                 </Swiper>
               ) : (
                 <div className="placeholder-device"></div>
               )}
            </div>
          </div>
        </div>
      </section>

      {/* Quick Action Buttons */}
      <section className="quick-actions-section">
        <div className="container">
          <a href={waLink} className="qa-btn qa-whatsapp" target="_blank" rel="noopener noreferrer">
            <FaWhatsapp size={20} /> Ready to Order Vape in Indiranagar ?
          </a>
          <a href="#products" className="qa-btn qa-browse">
            Browse Products <i className="fas fa-chevron-right" style={{ marginLeft: '6px', fontSize: '12px' }}></i>
          </a>
        </div>
      </section>



      {/* Best Selling Section */}
      <BestSellingSection />

      {/* Combined Trust Badges and About Image Section */}
      <section className="trust-badges-section">
        <div className="container">
          <div className="about-trust-layout">
            <div className="trust-column">
              <div className="trust-badge-card">
                <LuShieldCheck className="trust-badge-icon" />
                <h3>Age-verified</h3>
                <p>Strict 21+ verification on every order.</p>
              </div>
              <div className="trust-badge-card">
                <LuFlaskConical className="trust-badge-icon" />
                <h3>Lab-tested</h3>
                <p>Every batch screened for purity.</p>
              </div>
            </div>

            <div className="about-image-column">
              {about && about.images && about.images.length > 0 ? (
                <div className="about-image" style={{ width: '100%', margin: '0 auto' }}>
                  <Swiper
                    modules={[Autoplay, Pagination, EffectFade]}
                    autoplay={{ delay: 1500, disableOnInteraction: false }}
                    pagination={{ clickable: true }}
                    effect="fade"
                    loop={about.images.length > 1}
                    className="about-swiper"
                  >
                    {about.images.map((img, idx) => (
                      <SwiperSlide key={idx}>
                        <img loading="lazy" src={`${img}`} alt={`About Us ${idx}`} style={{ width: '100%', height: 'auto', borderRadius: '12px', objectFit: 'cover', maxHeight: '500px' }} />
                      </SwiperSlide>
                    ))}
                  </Swiper>
                </div>
              ) : null}
            </div>

            <div className="trust-column">
              <div className="trust-badge-card">
                <LuTruck className="trust-badge-icon" />
                <h3>Fast shipping</h3>
                <p>Discreet delivery, ships in 24h.</p>
              </div>
              <div className="trust-badge-card">
                <LuBadgeCheck className="trust-badge-icon" />
                <h3>Authentic only</h3>
                <p>Sourced direct from manufacturers.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Products Section */}
      <section id="products" className="products-section">
        <div className="container">
          <div className="section-header text-center">
            <h2>All <span className="cyan-text">Vape Products</span></h2>
            <p>Select your flavour and add to cart — delivered in 30-45 mins.</p>
          </div>
          <Suspense fallback={<div style={{minHeight: '200px'}}>Loading products...</div>}>
            <ProductsGrid />
          </Suspense>
        </div>
      </section>

      {/* Dynamic About Us Section */}
      {about && (
        <section id="about" className="about-section">
          <div className="container">
            <div className="about-two-columns">
              <div className="about-left-col">
                <p style={{ color: 'var(--primary-accent)', fontSize: '14px', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1.5px', fontWeight: '600' }}>ABOUT US</p>
                <h2 className="about-main-title">About Our <span className="cyan-text">Vape Shop Indiranagar</span></h2>
                <div className="about-text-content" dangerouslySetInnerHTML={{ __html: about.description }}></div>
                
                <div className="about-features-grid">
                  <div className="about-feature-card">
                    <div className="about-icon-wrapper"><FiShield className="about-icon" /></div>
                    <div className="about-feature-text">
                      <h4>Premium Selection</h4>
                      <p>Explore disposable vapes, pod devices, and bestselling options in Indiranagar.</p>
                    </div>
                  </div>
                  <div className="about-feature-card">
                    <div className="about-icon-wrapper"><FiArrowRight className="about-icon" /></div>
                    <div className="about-feature-text">
                      <h4>Easy Ordering</h4>
                      <p>Built for fast mobile browsing and simple order flow for local customers.</p>
                    </div>
                  </div>
                  <div className="about-feature-card">
                    <div className="about-icon-wrapper"><FiTruck className="about-icon" /></div>
                    <div className="about-feature-text">
                      <h4>Indiranagar Focus</h4>
                      <p>Created around local searches like vape shop Indiranagar and vape delivery Indiranagar.</p>
                    </div>
                  </div>
                  <div className="about-feature-card">
                    <div className="about-icon-wrapper"><FiStar className="about-icon" /></div>
                    <div className="about-feature-text">
                      <h4>Trending Picks</h4>
                      <p>Find trending and best-selling vape products in one clean section flow.</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="about-right-col">
                <div className="about-side-card">
                  <h3>Why customers visit this page</h3>
                  <p>People searching for the <strong>best vape shop in Indiranagar</strong>, <strong>vape shop Indiranagar</strong>, <strong>vape store Indiranagar</strong>, or <strong>disposable vape Indiranagar</strong> usually want a clear and trusted product browsing experience. This homepage is designed to support that intent with visible sections, product highlights, and local keyword relevance.</p>
                  <div className="about-tags-grid">
                    <span>Best Vape Shop in Indiranagar</span>
                    <span>Vape Shop Indiranagar</span>
                    <span>Vape Store Indiranagar</span>
                    <span>Buy Vape in Indiranagar</span>
                    <span>Disposable Vape Indiranagar</span>
                    <span>Pod System Indiranagar</span>
                  </div>
                </div>
                
                <div className="about-side-card">
                  <h3>Explore more</h3>
                  <p>Browse trending products, bestseller sections, and FAQ content to discover more from our vape shop Indiranagar collection and improve the customer journey on mobile and desktop.</p>
                </div>
                
                <div className="about-buttons-row">
                  <a href="/#products" className="btn-primary" style={{ padding: '12px 24px', fontWeight: 'bold' }}>SHOP VAPE PRODUCTS</a>
                  <a href="/#contact" className="btn-outline" style={{ padding: '12px 24px', fontWeight: 'bold' }}>CONTACT US</a>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Delivery Areas Section */}
      <DeliveryAreasSection />

      {/* Dynamic Why Choose Us Section */}
      {whyChooseUs && whyChooseUs.length > 0 && (
        <section id="why-choose-us" className="why-choose-section">
          <div className="container">
            <div className="section-header text-center">
              <p style={{ color: 'var(--primary-accent)', fontSize: '14px', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1.5px', fontWeight: '600' }}>WHY CHOOSE US</p>
              <h2 className="why-title">Why Customers Prefer Our <span className="cyan-text">Vape Shop Indiranagar</span></h2>
              <p className="why-subtitle">We focus on genuine products, responsive support, and a smooth ordering experience so you can shop with confidence from one of the best vape shop options in Indiranagar.</p>
            </div>
            <div className="features-grid">
              {whyChooseUs.map((item) => (
                <div className="feature-card" key={item.id}>
                  <div className="feature-icon-wrapper">
                    {item.icon ? (
                      <i className={`${item.icon} feature-icon`}></i>
                    ) : (
                      <FiCheckCircle className="feature-icon" />
                    )}
                  </div>
                  <h3>{item.title}</h3>
                  <p>{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* Contact Section */}
      <ContactSection />
    </div>
  );
};

export default Home;

"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import api from '../../services/api';
import './Footer.css';

const Footer = () => {
  const [contactInfo, setContactInfo] = useState({});
  const [categories, setCategories] = useState([]);

  const [footerInfo, setFooterInfo] = useState({});
  const [showAllCategories, setShowAllCategories] = useState(false);

  useEffect(() => {
    const fetchFooterData = async () => {
      try {
        const [contactRes, catRes, footerRes] = await Promise.all([
          api.get('/cms/contact-info'),
          api.get('/categories'),
          api.get('/cms/footer')
        ]);
        if (contactRes.data.success && contactRes.data.contactInfo) {
          setContactInfo(contactRes.data.contactInfo);
        }
        if (catRes.data.success && catRes.data.categories) {
          setCategories(catRes.data.categories.filter(c => c.status === 1 || c.status === 'active'));
        }
        if (footerRes.data.success && footerRes.data.footer) {
          setFooterInfo(footerRes.data.footer);
        }
      } catch (err) {
        console.error("Failed to load footer data", err);
      }
    };
    fetchFooterData();
  }, []);

  return (
    <footer className="public-footer" id="contact">
      <div className="container footer-grid">
        <div className="footer-col brand-col">
          <Link href="/" className="footer-logo">
            {footerInfo.footer_logo_text || "Vapeblr"}
          </Link>
          <p className="footer-desc">
            {footerInfo.footer_text 
              ? footerInfo.footer_text.replace(/Hyderabad|Bangalore|Bengaluru|Koramangala/gi, 'Indiranagar')
              : "Premium vape store in Indiranagar offering top-tier disposable vapes, e-liquids, and fast local delivery for adults 21+."}
          </p>
        </div>

        <div className="footer-col links-col">
          <h3>Shop by Categories</h3>
          <ul>
            {categories.slice(0, showAllCategories ? categories.length : 5).map(cat => (
              <li key={cat.id}>
                <Link href={`/?category=${cat.slug || cat.id}#products`}><i className="fas fa-angle-right" style={{marginRight: '8px', fontSize: '0.8em'}}></i>{cat.category_name}</Link>
              </li>
            ))}
            {categories.length > 5 && (
              <li>
                <button 
                  onClick={() => setShowAllCategories(!showAllCategories)}
                  style={{
                    background: 'none', 
                    border: 'none', 
                    color: 'var(--primary-accent)', 
                    cursor: 'pointer', 
                    padding: 0, 
                    fontFamily: 'inherit',
                    fontSize: '14px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    marginTop: '4px'
                  }}
                >
                  {showAllCategories ? 'Show Less' : 'Show More Categories'} 
                  <i className={`fas fa-chevron-${showAllCategories ? 'up' : 'down'}`} style={{fontSize: '0.8em'}}></i>
                </button>
              </li>
            )}
          </ul>
        </div>

        <div className="footer-col links-col">
          <h3>Quick Links</h3>
          <ul>
            <li><Link href="/"><i className="fas fa-angle-right" style={{marginRight: '8px', fontSize: '0.8em'}}></i>Home</Link></li>
            <li><Link href="/#products"><i className="fas fa-angle-right" style={{marginRight: '8px', fontSize: '0.8em'}}></i>Products</Link></li>
            <li><Link href="/#about"><i className="fas fa-angle-right" style={{marginRight: '8px', fontSize: '0.8em'}}></i>About Us</Link></li>
            <li><Link href="/#contact"><i className="fas fa-angle-right" style={{marginRight: '8px', fontSize: '0.8em'}}></i>Contact Us</Link></li>
          </ul>
        </div>

        <div className="footer-col contact-col">
          <h3>Contact Us</h3>
          <div className="contact-details">
            {contactInfo.phone && <p><i className="fas fa-phone-alt"></i> {contactInfo.phone}</p>}
            {contactInfo.email && <p><i className="fas fa-envelope"></i> {contactInfo.email}</p>}
            {contactInfo.address && <p><i className="fas fa-map-marker-alt"></i> {contactInfo.address}</p>}
          </div>
        </div>
      </div>
      
      <div className="container">
        <div className="nicotine-warning">
          <strong>WARNING:</strong> This product contains nicotine. Nicotine is an addictive chemical. Products intended for use by adults 21 years of age or older. Keep out of reach of children and pets.
        </div>
      </div>
      
      <div className="footer-bottom">
        <div className="container bottom-container">
          <p>
            {footerInfo.copyright_text 
              ? footerInfo.copyright_text.replace('{year}', new Date().getFullYear())
              : `© ${new Date().getFullYear()} Vapeblr. All rights reserved.`}
          </p>
          <div className="bottom-links">
            <Link href="/privacy-policy">Privacy</Link>
            <Link href="/terms">Terms</Link>
            <Link href="/age-policy">21+ Policy</Link>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;

"use client";

import React, { useEffect, useState } from 'react';
import { FaWhatsapp } from 'react-icons/fa';
import Link from 'next/link';
import api from '../../services/api';
import './CtaSection.css';

const CtaSection = () => {
  const [waLink, setWaLink] = useState('#');

  useEffect(() => {
    const fetchWhatsapp = async () => {
      try {
        const res = await api.get('/cms/whatsapp');
        const whatsapp = res.data?.whatsapp;
        if (res.data?.success && whatsapp?.business_number) {
          const message = whatsapp.default_message || 'Hello!';
          setWaLink(`https://wa.me/${whatsapp.business_number}?text=${encodeURIComponent(message)}`);
        }
      } catch (err) {
        console.error("Failed to load WhatsApp info", err);
      }
    };

    fetchWhatsapp();
  }, []);

  return (
    <section className="cta-global-section">
      <div className="cta-content-wrapper">
        <div className="cta-text">
          <h2>Ready to Order Vape in <span className="cyan-text">Indiranagar</span>?</h2>
          <p>Message us on WhatsApp — we'll confirm your order and dispatch within minutes.</p>
        </div>
        <div className="cta-buttons">
          <a href={waLink} className="cta-btn cta-wa-btn" target="_blank" rel="noopener noreferrer">
            <FaWhatsapp size={20} /> Order Now 
          </a>
          <Link href="/#products" className="cta-btn cta-browse-btn">
            Browse Products <i className="fas fa-chevron-right" style={{ fontSize: '12px' }}></i>
          </Link>
        </div>
      </div>
    </section>
  );
};

export default CtaSection;

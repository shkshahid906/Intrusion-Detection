"use client";

import React, { Suspense } from 'react';
import Header from '../../components/public/Header';
import Footer from '../../components/public/Footer';
import SEOTracker from '../../components/public/SEOTracker';
import CartDrawer from '../../components/public/CartDrawer';
import Faq from '../../components/public/Faq';
import CtaSection from '../../components/public/CtaSection';

export default function PublicLayout({ children }) {
  return (
    <div className="public-layout">
      <SEOTracker />
      <Suspense fallback={<div style={{height: '80px'}}></div>}>
        <Header />
      </Suspense>
      
      <main style={{ minHeight: '80vh', paddingTop: '80px' }}>
        {children}
      </main>

      <Faq />
      <CartDrawer />
      
      <CtaSection />
      <Footer />
    </div>
  );
}

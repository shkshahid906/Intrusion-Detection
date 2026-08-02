"use client";

import React from 'react';

export default function TermsOfService() {
  return (
    <div className="container" style={{ padding: '40px 20px', maxWidth: '800px', margin: '0 auto', color: 'var(--text-main)' }}>
      <h1 style={{ marginBottom: '20px', color: 'var(--white)' }}>Terms of Service</h1>
      <p style={{ marginBottom: '15px' }}>Welcome to Vape in Hyderabad. By accessing our website and placing an order, you agree to be bound by the following Terms of Service.</p>
      
      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Age Restriction</h2>
      <p style={{ marginBottom: '15px' }}>Our products are strictly for adults aged 21 and over. By agreeing to these terms, you verify that you are legally allowed to purchase nicotine products in India. We reserve the right to request age verification upon delivery.</p>

      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Delivery & Orders</h2>
      <p style={{ marginBottom: '15px' }}>We strive to provide same-day delivery across Hyderabad. However, delivery times are subject to traffic and weather conditions. We reserve the right to cancel any order if we suspect fraudulent activity or violation of our age policy.</p>

      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Product Disclaimer</h2>
      <p style={{ marginBottom: '15px' }}>Vaping products contain nicotine, a highly addictive substance. These products are not intended to diagnose, treat, cure, or prevent any disease. Use them at your own risk.</p>

      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Changes to Terms</h2>
      <p style={{ marginBottom: '15px' }}>We reserve the right to modify these terms at any time. Any changes will be effective immediately upon posting to this website.</p>
    </div>
  );
}

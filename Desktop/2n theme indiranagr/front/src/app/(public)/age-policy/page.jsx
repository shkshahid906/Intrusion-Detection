"use client";

import React from 'react';

export default function AgePolicy() {
  return (
    <div className="container" style={{ padding: '40px 20px', maxWidth: '800px', margin: '0 auto', color: 'var(--text-main)' }}>
      <h1 style={{ marginBottom: '20px', color: 'var(--white)' }}>21+ Age Policy</h1>
      
      <div style={{ padding: '20px', backgroundColor: 'rgba(255, 0, 0, 0.1)', borderLeft: '4px solid #ff4444', borderRadius: '8px', marginBottom: '30px' }}>
        <h2 style={{ color: '#ff4444', marginTop: 0, marginBottom: '10px' }}>STRICTLY FOR ADULTS 21+</h2>
        <p style={{ margin: 0 }}>Vape in Indiranagar maintains a strict zero-tolerance policy for underage vaping. All of our products are strictly intended for adults aged 21 and older.</p>
      </div>

      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Age Verification Process</h2>
      <p style={{ marginBottom: '15px' }}>To prevent unauthorized purchases by minors, we reserve the right to require a government-issued ID upon delivery. If the receiver cannot prove they are 21 years of age or older, the delivery will be canceled immediately without a refund.</p>

      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Commitment to the Community</h2>
      <p style={{ marginBottom: '15px' }}>We are committed to operating responsibly within the community of Indiranagar. We actively train our delivery partners to strictly enforce this 21+ policy at the door.</p>

      <h2 style={{ marginTop: '30px', marginBottom: '15px', color: 'var(--white)' }}>Falsifying Age</h2>
      <p style={{ marginBottom: '15px' }}>Falsifying your age to purchase vaping products is illegal and is a violation of our Terms of Service. Anyone found doing so will be permanently banned from our platform and reported to the relevant authorities if necessary.</p>
    </div>
  );
}

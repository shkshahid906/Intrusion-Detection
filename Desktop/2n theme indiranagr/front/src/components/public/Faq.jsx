"use client";

import React, { useState } from 'react';
import './Faq.css';

const faqData = [
  {
    question: "Do you offer fast delivery in Indiranagar?",
    answer: "Yes, we offer fast delivery across major areas in Indiranagar including HAL 2nd Stage, Defence Colony, Jeevan Bheema Nagar, Domlur, Ulsoor, CV Raman Nagar, and surrounding locations."
  },
  {
    question: "Which areas in Indiranagar do you deliver to?",
    answer: "We serve customers across Indiranagar including HAL 2nd Stage, HAL 3rd Stage, Defence Colony, Jeevan Bheema Nagar, Domlur, EGL, Ulsoor, CV Raman Nagar, and surrounding locations."
  },
  {
    question: "What products are available?",
    answer: "We offer a wide range of premium disposable devices, pod systems, refillable devices, pods, nicotine salts, and accessories from leading international brands."
  },
  {
    question: "Do you provide same-day delivery in Indiranagar?",
    answer: "Yes, same-day delivery is available in select locations in and around Indiranagar depending on product availability and delivery slot."
  },
  {
    question: "How can I place an order?",
    answer: "You can browse products on our website and contact us through WhatsApp for quick assistance, product availability, and delivery support."
  },
  {
    question: "Are your products authentic?",
    answer: "We focus on premium-quality products and customer satisfaction with careful quality checks before dispatch."
  },
  {
    question: "Which are the popular areas you deliver in Indiranagar?",
    answer: "We frequently deliver to HAL 2nd Stage, HAL 3rd Stage, Defence Colony, Jeevan Bheema Nagar, Domlur, Ulsoor, and CV Raman Nagar."
  },
  {
    question: "Can I get help choosing the right device?",
    answer: "Yes, our support team can help you choose a suitable device based on your preferences and usage requirements."
  },
  {
    question: "Do you offer customer support after purchase?",
    answer: "Yes, customer support is available for order-related assistance and product guidance."
  },
  {
    question: "How do I contact Vape Store Indiranagar?",
    answer: "You can contact us directly through WhatsApp for fast responses regarding product availability, delivery, and order support."
  }
];

const Faq = () => {
  const [activeIndex, setActiveIndex] = useState(null);
  const [showAllFaqs, setShowAllFaqs] = useState(false);

  const INITIAL_FAQ_COUNT = 4;
  const displayedFaqs = showAllFaqs ? faqData : faqData.slice(0, INITIAL_FAQ_COUNT);
  const hasMoreFaqs = faqData.length > INITIAL_FAQ_COUNT;

  const toggleAccordion = (index) => {
    setActiveIndex(activeIndex === index ? null : index);
  };

  return (
    <section id="faq" className="faq-section">
      <div className="container">
        <div className="faq-header">
          <p style={{ color: 'var(--primary-accent)', fontSize: '14px', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1.5px', fontWeight: '600' }}>SUPPORT</p>
          <h2 className="faq-title">Frequently Asked Questions</h2>
          <p className="faq-subtitle">Everything you need to know about our products and services.</p>
        </div>
        
        <div className="faq-list">
          {displayedFaqs.map((item, index) => {
            const isActive = activeIndex === index;
            
            return (
              <div 
                key={index} 
                className={`faq-item ${isActive ? 'active' : ''}`}
                onClick={() => toggleAccordion(index)}
              >
                <div className="faq-question">
                  <h3>{item.question}</h3>
                  <div className={`faq-icon ${isActive ? 'active' : ''}`}>
                    {isActive ? (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                      </svg>
                    ) : (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                      </svg>
                    )}
                  </div>
                </div>
                <div className="faq-answer-wrapper" style={{ maxHeight: isActive ? '200px' : '0' }}>
                  <div className="faq-answer">
                    <p>{item.answer}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {hasMoreFaqs && (
          <div className="faq-view-more-container">
            <button 
              className="faq-view-more-btn"
              onClick={() => setShowAllFaqs(!showAllFaqs)}
              aria-expanded={showAllFaqs}
            >
              <span>{showAllFaqs ? 'Show Less FAQs' : `View More FAQs (${faqData.length - INITIAL_FAQ_COUNT} More)`}</span>
              <svg 
                width="16" 
                height="16" 
                viewBox="0 0 24 24" 
                fill="none" 
                stroke="currentColor" 
                strokeWidth="2.5" 
                strokeLinecap="round" 
                strokeLinejoin="round"
                style={{ transform: showAllFaqs ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.3s ease' }}
              >
                <polyline points="6 9 12 15 18 9"></polyline>
              </svg>
            </button>
          </div>
        )}
      </div>
    </section>
  );
};

export default Faq;

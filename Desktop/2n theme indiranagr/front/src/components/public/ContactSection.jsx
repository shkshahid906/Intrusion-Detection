"use client";

import React, { useState } from 'react';
import api from '../../services/api';
import './ContactSection.css';

const ContactSection = () => {
  const formatPhone = (phone) => {
    const digits = (phone || '').replace(/\D/g, '');
    if (digits.length === 10) {
      return `+91 ${digits.slice(0, 5)} ${digits.slice(5)}`;
    }
    return phone || '';
  };

  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    email: '',
    message: ''
  });
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null); // { type: 'success' | 'error', message: '' }
  const [contactInfo, setContactInfo] = useState({ phone: '+91 99999 99999', email: 'support@vapesindiranagar.com' });

  React.useEffect(() => {
    const fetchContactInfo = async () => {
      try {
        const res = await api.get('/cms/contact-info');
        if (res.data.success && res.data.contactInfo) {
          setContactInfo({
            phone: res.data.contactInfo.phone || '+91 99999 99999',
            email: res.data.contactInfo.email || 'support@vapesindiranagar.com'
          });
        }
      } catch (err) {
        console.error("Failed to fetch contact info", err);
      }
    };
    fetchContactInfo();
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    if (name === 'phone') {
      const numbersOnly = value.replace(/[^0-9]/g, '');
      if (numbersOnly.length <= 10) {
        setFormData({ ...formData, [name]: numbersOnly });
      }
      return;
    }
    setFormData({
      ...formData,
      [name]: value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const response = await api.post('/enquiries', {
        ...formData,
        type: 'ContactForm'
      });

      if (response.data.success) {
        setStatus({ type: 'success', message: 'Your enquiry has been submitted successfully! We will get back to you soon.' });
        setFormData({ name: '', phone: '', email: '', message: '' }); // Reset form
      } else {
        setStatus({ type: 'error', message: response.data.error || 'Failed to submit enquiry. Please try again.' });
      }
    } catch (err) {
      console.error('Error submitting enquiry:', err);
      setStatus({ type: 'error', message: 'Something went wrong. Please check your connection and try again.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <section id="contact" className="contact-section">
      <div className="container">
        <div className="contact-wrapper">
          <div className="contact-info">
            <span className="pill-tag">Get in Touch</span>
            <h2>Have a question? We're here to help.</h2>
            <p>Whether you need help choosing the right device or have a question about your order, our team is ready to assist you.</p>
            
            <div className="info-cards">
              <div className="info-card">
                <div className="info-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
                  </svg>
                </div>
                <div>
                  <h4>Phone Support</h4>
                  <a href={`tel:${(contactInfo.phone || '').replace(/[^0-9+]/g, '')}`} className="contact-link">{formatPhone(contactInfo.phone) || 'Phone'}</a>
                </div>
              </div>
              <div className="info-card">
                <div className="info-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                    <polyline points="22,6 12,13 2,6"></polyline>
                  </svg>
                </div>
                <div>
                  <h4>Email Us</h4>
                  <a href={`mailto:${contactInfo.email}`} className="contact-link">{contactInfo.email}</a>
                </div>
              </div>
            </div>
          </div>

          <div className="contact-form-container card">
            <h3>Send an Enquiry</h3>
            {status && (
              <div className={`status-message ${status.type}`}>
                {status.message}
              </div>
            )}
            <form onSubmit={handleSubmit} className="contact-form">
              <div className="form-group">
                <label htmlFor="name">Full Name *</label>
                <input 
                  type="text" 
                  id="name" 
                  name="name" 
                  value={formData.name}
                  onChange={handleChange}
                  placeholder="John Doe"
                  required
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="phone">Phone Number *</label>
                <input 
                  type="tel" 
                  id="phone" 
                  name="phone" 
                  value={formData.phone}
                  onChange={handleChange}
                  placeholder="9999999999"
                  maxLength="10"
                  pattern="[0-9]{10}"
                  title="Please enter a valid 10-digit mobile number"
                  required
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="email">Email Address</label>
                <input 
                  type="email" 
                  id="email" 
                  name="email" 
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="john@example.com"
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="message">Message *</label>
                <textarea 
                  id="message" 
                  name="message" 
                  value={formData.message}
                  onChange={handleChange}
                  placeholder="How can we help you?"
                  rows="4"
                  required
                ></textarea>
              </div>
              
              <button type="submit" className="btn-primary submit-btn" disabled={loading}>
                {loading ? 'Sending...' : 'Send Enquiry'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ContactSection;

"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import '../AdminPages.css';

const About = () => {
  const [aboutData, setAboutData] = useState({ title: '', description: '' });
  const [loading, setLoading] = useState(true);
  const [selectedImages, setSelectedImages] = useState([]);
  const [existingImages, setExistingImages] = useState([]);

  const fetchAbout = async () => {
    try {
      const response = await api.get('/cms/about');
      if (response.data.success && response.data.about) {
        setAboutData({
          title: response.data.about.title || '',
          description: response.data.about.description || ''
        });
        setExistingImages(response.data.about.images || []);
      }
    } catch (error) {
      toast.error('Failed to load About Us content');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAbout();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setAboutData(prev => ({ ...prev, [name]: value }));
  };

  const handleFileChange = (e) => {
    setSelectedImages(Array.from(e.target.files));
  };

  const removeExistingImage = (index) => {
    setExistingImages(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append('title', aboutData.title);
    formData.append('description', aboutData.description);
    formData.append('existingImages', JSON.stringify(existingImages));
    
    selectedImages.forEach(file => {
      formData.append('images', file);
    });

    try {
      await api.put('/cms/about', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      toast.success('About Us updated successfully');
      setSelectedImages([]);
      fetchAbout();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Manage About Us Page</h2>
      </div>

      <div className="admin-form-container" style={{ maxWidth: '1000px', padding: '5px', background: 'var(--bg-card)', borderRadius: '8px' }}>
        <form className="admin-form" onSubmit={handleSubmit} >
          
          {/* Left Side: Text Content */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="form-group" >
              <label>Title</label>
              <input 
                type="text" 
                name="title" 
                value={aboutData.title} 
                onChange={handleInputChange} 
                required 
              />
            </div>

            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Description (HTML allowed)</label>
              <textarea 
                name="description" 
                value={aboutData.description} 
                onChange={handleInputChange} 
                style={{ flex: 1, minHeight: '150px', resize: 'vertical' }} 
                required
              ></textarea>
            </div>
          </div>

          {/* Right Side: Image & Actions */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="form-group" >
              <label>Cover Images</label>
              {existingImages.length > 0 && (
                <div style={{ marginBottom: '15px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                  {existingImages.map((img, idx) => (
                    <div key={idx} style={{ position: 'relative', width: '80px', height: '80px' }}>
                      <img loading="lazy" src={`${img}`} alt="About Us" style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '8px', border: '1px solid var(--border-color)' }} />
                      <button type="button" onClick={() => removeExistingImage(idx)} style={{ position: 'absolute', top: '-5px', right: '-5px', background: 'red', color: 'var(--bg-card)', borderRadius: '50%', border: 'none', cursor: 'pointer', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>&times;</button>
                    </div>
                  ))}
                </div>
              )}
              <input type="file" name="images" accept="image/*" multiple onChange={handleFileChange} />
              <small style={{display: 'block', marginTop: '5px', color: 'var(--text-muted)'}}>Select multiple images to create a swiper/slider on the frontend.</small>
            </div>

            <div style={{ marginTop: 'auto' }}>
              <button type="submit" className="btn-primary" style={{ padding: '12px 24px', fontSize: '16px', width: '100%' }}>
                Save Changes
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default About;

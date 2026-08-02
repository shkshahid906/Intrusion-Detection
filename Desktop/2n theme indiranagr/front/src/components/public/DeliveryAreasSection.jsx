"use client";

import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import './DeliveryAreasSection.css';

const DEFAULT_AREAS = [
  { id: 'def-1', main_area: 'HAL 2nd Stage & Defence Colony', sub_areas: '100 Feet Road, 12th Main, 100ft Rd, Doopanahalli', link_url: '/#products', link_text: 'Shop now' },
  { id: 'def-2', main_area: 'HAL 3rd Stage & Jeevan Bheema Nagar', sub_areas: 'New Tippasandra, Geethanjali Layout, Kodihalli', link_url: '/#products', link_text: 'Shop now' },
  { id: 'def-3', main_area: 'Domlur & EGL', sub_areas: 'Domlur Layout, Amarjyothi Layout, Wind Tunnel Road', link_url: '/#products', link_text: 'Shop now' },
  { id: 'def-4', main_area: 'Ulsoor & Cambridge Layout', sub_areas: 'Gupta Layout, Jogupalya, MG Road', link_url: '/#products', link_text: 'Shop now' },
  { id: 'def-5', main_area: 'CV Raman Nagar', sub_areas: 'Kaggadasapura, GM Palya, Malleshpalya', link_url: '/#products', link_text: 'Shop now' },
  { id: 'def-6', main_area: 'Koramangala & HSR Layout', sub_areas: '1st Block, 4th Block, HSR Layout Sectors', link_url: '/#products', link_text: 'Shop now' },
];

const DeliveryAreasSection = () => {
  const [areas, setAreas] = useState(DEFAULT_AREAS);
  const [showAll, setShowAll] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth <= 768);
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    const fetchAreas = async () => {
      try {
        const response = await api.get('/cms/delivery-areas');
        if (response.data.success && Array.isArray(response.data.areas) && response.data.areas.length > 0) {
          const activeAreas = response.data.areas.filter(a => a.status === 'active');
          if (activeAreas.length > 0) {
            setAreas(activeAreas);
          }
        }
      } catch (error) {
        console.error("Error fetching delivery areas", error);
      }
    };
    fetchAreas();
  }, []);

  if (areas.length === 0) return null;

  const INITIAL_COUNT = isMobile ? 4 : 5;
  const displayedAreas = showAll ? areas : areas.slice(0, INITIAL_COUNT);
  const hasMore = areas.length > INITIAL_COUNT;

  return (
    <section id="shipping" className="delivery-areas-section">
      <div className="container">
        <div className="delivery-areas-header">
          <p className="delivery-label">DELIVERY AREAS</p>
          <h2><span className="cyan-text">Vape Delivery</span> Across All of <span className="cyan-text">Indiranagar</span></h2>
          <p className="delivery-subtitle">
            We cover {areas.length} major areas — click your location to see local delivery details, sublocations, and order options.
          </p>
        </div>
        
        <div className="delivery-grid">
          {displayedAreas.map((area) => (
            <a href={area.link_url || '/#products'} className="delivery-card" key={area.id}>
              <h3 className="area-title">{area.main_area}</h3>
              <p className="sub-areas">{area.sub_areas}</p>
              <span className="delivery-link">
                {(area.link_text || 'Shop now').replace(/(?:\s*→|\s*&rarr;|\s*>)$/, '')} <i className="fas fa-chevron-right" style={{ fontSize: '12px', marginLeft: '6px' }}></i>
              </span>
            </a>
          ))}
        </div>

        {hasMore && (
          <div className="delivery-view-more-container">
            <button 
              className="delivery-view-more-btn"
              onClick={() => setShowAll(!showAll)}
              aria-expanded={showAll}
            >
              <span>{showAll ? 'Show Less Areas' : `View More Areas (${areas.length - INITIAL_COUNT} More)`}</span>
              <i className={`fas fa-chevron-${showAll ? 'up' : 'down'}`}></i>
            </button>
          </div>
        )}
      </div>
    </section>
  );
};

export default DeliveryAreasSection;

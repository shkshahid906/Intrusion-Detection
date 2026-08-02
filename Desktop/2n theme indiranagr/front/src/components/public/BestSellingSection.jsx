"use client";

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import api from '../../services/api';
import ProductCard from './ProductCard';
import './ProductsGrid.css'; // Reusing the same grid styles
import { useAddToCart } from '../../hooks/useAddToCart';

const BestSellingSection = () => {
  const [bestSellers, setBestSellers] = useState([]);
  const [loading, setLoading] = useState(true);
  
  const handleAddToCart = useAddToCart();
  const navigate = useRouter();

  useEffect(() => {
    const fetchBestSellers = async () => {
      try {
        const response = await api.get('/products');
        if (response.data.success && response.data.products) {
          // Filter active, sort by sales_count descending, take top 5
          const activeProducts = response.data.products.filter(p => p.status === 1 || p.status === 'active');
          const sorted = activeProducts.sort((a, b) => (b.sales_count || 0) - (a.sales_count || 0));
          setBestSellers(sorted.slice(0, 8));
        }
      } catch (err) {
        console.error("Failed to load best sellers", err);
      } finally {
        setLoading(false);
      }
    };
    fetchBestSellers();
  }, []);



  if (loading || bestSellers.length === 0) return null;

  return (
    <section className="best-selling-section">
      <div className="container">
        <div className="section-header text-center best-selling-header">
          <h2 className="trending-title">
            Trending <span className="cyan-text">Vape Products</span> in Indiranagar
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '16px' }}>
            Our most popular vapes based on actual sales.
          </p>
        </div>
        
        <div className="products-grid best-selling-grid">
          {bestSellers.map((product, index) => (
            <ProductCard 
              key={product.id} 
              product={product} 
              index={index}
              onAdd={handleAddToCart}
            />
          ))}
        </div>
        
        <div className="view-all-wrapper">
          <button 
            className="btn-outline" 
            onClick={() => navigate.push('/#products')}
            style={{ padding: '10px 30px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}
          >
            View All Products <i className="fas fa-chevron-right" style={{ marginLeft: '6px', fontSize: '12px' }}></i>
          </button>
        </div>
      </div>
    </section>
  );
};

export default BestSellingSection;

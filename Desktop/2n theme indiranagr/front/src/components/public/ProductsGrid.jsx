"use client";

import React, { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import api from '../../services/api';
import ProductCard from './ProductCard';
import './ProductsGrid.css';
import { useAddToCart } from '../../hooks/useAddToCart';

const ProductsGrid = () => {
  const [products, setProducts] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  
  const searchParams = useSearchParams();
  const searchQuery = searchParams.get('search') || '';
  const categoryQuery = searchParams.get('category') || 'All';

  const [activeCategory, setActiveCategory] = useState(categoryQuery);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  useEffect(() => {
    setActiveCategory(searchParams.get('category') || 'All');
    setCurrentPage(1);
  }, [searchParams]);

  const handleAddToCart = useAddToCart();
  const router = useRouter();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [prodRes, catRes] = await Promise.all([
          api.get('/products'),
          api.get('/categories')
        ]);
        
        if (prodRes.data.success && prodRes.data.products) {
          setProducts(prodRes.data.products.filter(p => p.status === 1 || p.status === 'active'));
        }
        if (catRes.data.success && catRes.data.categories) {
          setCategories(catRes.data.categories.filter(c => c.status === 1 || c.status === 'active'));
        }
      } catch (err) {
        console.error("Failed to load products", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const filteredProducts = products.filter(p => {
    const matchesCategory = activeCategory === 'All' || p.category_id == activeCategory || p.category_slug === activeCategory;
    const searchLower = searchQuery.trim().toLowerCase();
    if (!searchLower) return matchesCategory;

    const nameStr = (p.name || '').toLowerCase();
    const descStr = (p.description || '').toLowerCase();
    const shortDescStr = (p.short_description || '').toLowerCase();
    const catStr = (p.category_name || '').toLowerCase();
    const keywordsStr = (p.seo_keywords || '').toLowerCase();
    const nicStr = (p.nicotine_strength || '').toLowerCase();
    
    // Check matching flavours
    const flavourMatch = Array.isArray(p.flavours) && p.flavours.some(f => 
      (f.flavour_name || '').toLowerCase().includes(searchLower)
    );

    const matchesSearch = nameStr.includes(searchLower) || 
                          descStr.includes(searchLower) ||
                          shortDescStr.includes(searchLower) ||
                          catStr.includes(searchLower) ||
                          keywordsStr.includes(searchLower) ||
                          nicStr.includes(searchLower) ||
                          flavourMatch;
                          
    return matchesCategory && matchesSearch;
  });

  const totalPages = Math.ceil(filteredProducts.length / itemsPerPage);
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentProducts = filteredProducts.slice(indexOfFirstItem, indexOfLastItem);

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
    const element = document.getElementById('products');
    if (element) {
      const y = element.getBoundingClientRect().top + window.scrollY - 90;
      window.scrollTo({ top: y, behavior: 'smooth' });
    }
  };

  if (loading) return <div className="loading-spinner">Loading...</div>;

  return (
    <div className="products-container" id="products">
      {/* Categories Filter */}
      <div className="category-filters-container">
        <div className="category-filters no-scrollbar">
          <button 
            className={`pill-tag filter-btn ${activeCategory === 'All' ? 'active' : 'outline'}`}
            onClick={() => {
              setActiveCategory('All');
              const params = new URLSearchParams(searchParams.toString());
              params.delete('category');
              router.push(`?${params.toString()}`, { scroll: false });
            }}
          >
            All
          </button>
          {categories.map(cat => (
            <button 
              key={cat.id} 
              className={`pill-tag filter-btn ${activeCategory == (cat.slug || cat.id) || activeCategory == cat.id ? 'active' : 'outline'}`}
              onClick={() => {
                const targetCat = cat.slug || cat.id;
                setActiveCategory(targetCat);
                const params = new URLSearchParams(searchParams.toString());
                params.set('category', targetCat);
                router.push(`?${params.toString()}`, { scroll: false });
              }}
            >
              {cat.category_name}
            </button>
          ))}
        </div>
      </div>
      
      {searchQuery && (
        <div className="search-results-info" style={{marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
          <div style={{color: 'var(--text-secondary)'}}>
            Showing results for: <strong style={{color: 'var(--white)'}}>"{searchQuery}"</strong>
          </div>
          <button 
            onClick={() => router.push('/#products', { scroll: false })} 
            style={{background: 'transparent', border: '1px solid var(--border-color)', color: 'var(--white)', padding: '6px 12px', borderRadius: '8px', cursor: 'pointer', fontSize: '12px', fontFamily: 'Inter'}}
          >
            Clear Search
          </button>
        </div>
      )}

      {/* Grid */}
      <div className="products-grid">
        {currentProducts.map((product, index) => (
          <ProductCard 
            key={product.id} 
            product={product} 
            index={index}
            onAdd={handleAddToCart}
          />
        ))}
        {filteredProducts.length === 0 && (
          <div className="no-products">
            <p>No products found {searchQuery ? `for "${searchQuery}"` : 'in this category'}.</p>
            {searchQuery && (
              <button 
                onClick={() => router.push('/#products', { scroll: false })}
                style={{marginTop: '16px', background: 'var(--primary-accent)', color: 'var(--text-button)', border: 'none', padding: '10px 20px', borderRadius: '8px', cursor: 'pointer', fontWeight: 'bold'}}
              >
                Clear Search
              </button>
            )}
          </div>
        )}
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button 
            className="page-btn" 
            onClick={() => handlePageChange(currentPage - 1)}
            disabled={currentPage === 1}
          >
            Prev
          </button>
          
          {[...Array(totalPages)].map((_, i) => (
            <button 
              key={i + 1} 
              className={`page-btn ${currentPage === i + 1 ? 'active' : ''}`}
              onClick={() => handlePageChange(i + 1)}
            >
              {i + 1}
            </button>
          ))}
          
          <button 
            className="page-btn" 
            onClick={() => handlePageChange(currentPage + 1)}
            disabled={currentPage === totalPages}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

export default ProductsGrid;

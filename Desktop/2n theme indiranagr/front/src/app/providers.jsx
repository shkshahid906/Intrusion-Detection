"use client";

import { ToastContainer } from 'react-toastify';
import { AuthProvider } from '../context/AuthContext';
import { CartProvider } from '../context/CartContext';
import { HelmetProvider } from 'react-helmet-async';

export function Providers({ children }) {
  return (
    <HelmetProvider>
      <AuthProvider>
        <CartProvider>
        <style dangerouslySetInnerHTML={{__html: `
          div.Toastify__toast {
            background: rgba(19, 19, 19, 0.85) !important;
            border: 1px solid #242424 !important;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5), 0 0 15px rgba(0, 184, 255, 0.18) !important;
            backdrop-filter: blur(12px) !important;
            -webkit-backdrop-filter: blur(12px) !important;
            border-radius: 12px !important;
            font-family: 'Poppins', sans-serif !important;
          }
          div.Toastify__toast-theme--dark {
            background: rgba(19, 19, 19, 0.85) !important;
          }
          div.Toastify__toast-body {
            font-family: 'Poppins', sans-serif !important;
            font-size: 14px !important;
            color: #FFFFFF !important;
          }
          .Toastify__progress-bar {
            height: 3px !important;
          }
          .Toastify__progress-bar--success {
            background: #4CAF50 !important;
          }
          .Toastify__progress-bar--warning {
            background: #F3A51A !important;
          }
          .Toastify__progress-bar--error {
            background: #E53935 !important;
          }
        `}} />
        <ToastContainer 
          position="top-right" 
          autoClose={3000} 
          theme="dark" 
        />
        {children}
      </CartProvider>
    </AuthProvider>
    </HelmetProvider>
  );
}

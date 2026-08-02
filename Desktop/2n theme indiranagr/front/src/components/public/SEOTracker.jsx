"use client";

import React, { useState, useEffect } from 'react';
import { Helmet } from 'react-helmet-async';
import api from '../../services/api';

const SEOTracker = () => {
  const [seo, setSeo] = useState(null);

  useEffect(() => {
    const fetchSEO = async () => {
      try {
        const res = await api.get('/seo/settings');
        if (res.data.success) {
          setSeo(res.data.seoSettings);
        }
      } catch (err) {
        console.error("Failed to load SEO settings", err);
      }
    };
    fetchSEO();
  }, []);

  if (!seo) return null;

  return (
    <Helmet>
      {/* Standard Meta Tags */}
      {seo.meta_title && <title>{seo.meta_title}</title>}
      {seo.meta_description && <meta name="description" content={seo.meta_description} />}
      {seo.meta_keywords && <meta name="keywords" content={seo.meta_keywords} />}
      
      {/* Search Console */}
      {seo.search_console_verification && (
        <meta name="google-site-verification" content={seo.search_console_verification} />
      )}

      {/* Analytics (Normally injected in index.html, but we can load scripts dynamically here if needed. For now just storing them) */}
      {seo.google_analytics_id && (
        <script async src={`https://www.googletagmanager.com/gtag/js?id=${seo.google_analytics_id}`}></script>
      )}
      {seo.google_analytics_id && (
        <script>
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', '${seo.google_analytics_id}');
          `}
        </script>
      )}

      {seo.meta_pixel_id && (
        <script>
          {`
            !function(f,b,e,v,n,t,s)
            {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
            n.callMethod.apply(n,arguments):n.queue.push(arguments)};
            if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
            n.queue=[];t=b.createElement(e);t.async=!0;
            t.src=v;s=b.getElementsByTagName(e)[0];
            s.parentNode.insertBefore(t,s)}(window, document,'script',
            'https://connect.facebook.net/en_US/fbevents.js');
            fbq('init', '${seo.meta_pixel_id}');
            fbq('track', 'PageView');
          `}
        </script>
      )}
    </Helmet>
  );
};

export default SEOTracker;

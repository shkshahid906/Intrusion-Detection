import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || '/api',
});

// Cache to deduplicate simultaneous requests (prevents 429 Too Many Requests)
const pendingRequests = new Map();

const originalGet = api.get;
api.get = async (url, config) => {
  // Only deduplicate public API endpoints, ignore admin ones just in case
  if (url.includes('/admin/')) {
    return originalGet.call(api, url, config);
  }

  const cacheKey = url + JSON.stringify(config || {});
  
  if (pendingRequests.has(cacheKey)) {
    return pendingRequests.get(cacheKey);
  }

  const requestPromise = originalGet.call(api, url, config)
    .finally(() => {
      // Cache the promise for 5 seconds to handle rapid re-renders/mounts
      setTimeout(() => {
        pendingRequests.delete(cacheKey);
      }, 5000);
    });

  pendingRequests.set(cacheKey, requestPromise);
  return requestPromise;
};

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Don't auto-logout if we're trying to log in
      if (!error.config.url.includes('/auth/login')) {
        localStorage.removeItem('token');
        window.location.href = '/admin/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;

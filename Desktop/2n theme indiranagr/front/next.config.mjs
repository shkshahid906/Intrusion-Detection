/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Allow Cloudflare tunnels to connect to Next.js dev server without being blocked
  allowedDevOrigins: [
    'starter-jefferson-alert-pressure.trycloudflare.com',
    'integrated-tracy-demo-rendered.trycloudflare.com',
  ],
  async rewrites() {
    return [
      {
        source: '/uploads/:path*',
        destination: 'https://api.vapeshopindiranagar.com/uploads/:path*' // Connects to your local Node.js backend
      },
      {
        source: '/api/:path*',
        destination: 'https://api.vapeshopindiranagar.com/api/:path*' // Connects to your local Node.js backend
      }
    ]
  }
};

export default nextConfig;

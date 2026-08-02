import { NextResponse } from 'next/server';

export async function GET(request, { params }) {
  try {
    const { enc } = await params;
    const decodedUrl = Buffer.from(enc, 'base64').toString('utf-8');
    
    // Validate that it's requesting an upload to prevent SSRF
    if (!decodedUrl.startsWith('/uploads/')) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    // Fetch the image from the local backend securely
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';
    const res = await fetch(`${backendUrl}${decodedUrl}`);
    
    if (!res.ok) {
      return new NextResponse('Image not found', { status: 404 });
    }

    const buffer = await res.arrayBuffer();
    return new NextResponse(buffer, {
      headers: {
        'Content-Type': res.headers.get('Content-Type') || 'image/jpeg',
        'Cache-Control': 'public, max-age=31536000, immutable',
      }
    });
  } catch (err) {
    return new NextResponse('Error loading image', { status: 500 });
  }
}

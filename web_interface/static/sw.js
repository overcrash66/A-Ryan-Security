/**
 * Service Worker for A-Ryan Security Application
 * Handles caching of static assets for improved performance
 */

const CACHE_NAME = 'esl-pro-v1.0.0';
const STATIC_CACHE_NAME = 'esl-pro-static-v1.0.0';
const API_CACHE_NAME = 'esl-pro-api-v1.0.0';

// Assets to cache immediately
const STATIC_ASSETS = [
    '/static/style.css',
    '/static/performance.css',
    '/static/performance.js',
    'https://cdn.socket.io/4.7.2/socket.io.min.js'
];

// API endpoints to cache
const CACHEABLE_APIS = [
    '/api/status/av',
    '/api/status/fw',
    '/api/status/net',
    '/api/status/traffic',
    '/api/status/batch',
    '/api/history/batch'
];

// Install event - cache static assets
self.addEventListener('install', event => {
    console.log('ServiceWorker installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE_NAME)
            .then(cache => {
                console.log('Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                console.log('Static assets cached successfully');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('Error caching static assets:', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
    console.log('ServiceWorker activating...');
    
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== STATIC_CACHE_NAME && 
                            cacheName !== API_CACHE_NAME &&
                            cacheName !== CACHE_NAME) {
                            console.log('Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('ServiceWorker activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - handle requests with caching strategy
self.addEventListener('fetch', event => {
    const request = event.request;
    const url = new URL(request.url);
    
    // Skip non-GET requests
    if (request.method !== 'GET') {
        return;
    }
    
    // Handle static assets
    if (isStaticAsset(url.pathname)) {
        event.respondWith(handleStaticAsset(request));
        return;
    }
    
    // Handle API requests
    if (isAPIRequest(url.pathname)) {
        event.respondWith(handleAPIRequest(request));
        return;
    }
    
    // Handle page requests
    if (isPageRequest(url.pathname)) {
        event.respondWith(handlePageRequest(request));
        return;
    }
    
    // Default: network first
    event.respondWith(fetch(request));
});

// Static asset handling - Cache First strategy
async function handleStaticAsset(request) {
    try {
        const cache = await caches.open(STATIC_CACHE_NAME);
        const cachedResponse = await cache.match(request);
        
        if (cachedResponse) {
            console.log('Static asset served from cache:', request.url);
            return cachedResponse;
        }
        
        console.log('Static asset fetched from network:', request.url);
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.error('Error handling static asset:', error);
        return new Response('Asset not available', { status: 404 });
    }
}

// API request handling - Network First with cache fallback
async function handleAPIRequest(request) {
    try {
        const cache = await caches.open(API_CACHE_NAME);
        
        // Try network first for fresh data
        try {
            const networkResponse = await fetch(request);
            
            if (networkResponse.ok) {
                // Cache successful API responses for 5 minutes
                const responseClone = networkResponse.clone();
                setTimeout(() => {
                    cache.put(request, responseClone);
                }, 0);
                
                console.log('API served from network:', request.url);
                return networkResponse;
            }
        } catch (networkError) {
            console.log('Network failed, trying cache:', request.url);
        }
        
        // Fallback to cache
        const cachedResponse = await cache.match(request);
        if (cachedResponse) {
            console.log('API served from cache:', request.url);
            return cachedResponse;
        }
        
        return new Response(JSON.stringify({
            status: 'error',
            error: 'Service temporarily unavailable'
        }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        console.error('Error handling API request:', error);
        return new Response(JSON.stringify({
            status: 'error',
            error: 'Service error'
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// Page request handling - Network First
async function handlePageRequest(request) {
    try {
        const networkResponse = await fetch(request);
        console.log('Page served from network:', request.url);
        return networkResponse;
    } catch (error) {
        console.error('Error loading page:', error);
        return new Response('Page temporarily unavailable', { status: 503 });
    }
}

// Helper functions
function isStaticAsset(pathname) {
    return pathname.startsWith('/static/') || 
           pathname.endsWith('.css') || 
           pathname.endsWith('.js') || 
           pathname.endsWith('.ico');
}

function isAPIRequest(pathname) {
    return pathname.startsWith('/api/') || CACHEABLE_APIS.includes(pathname);
}

function isPageRequest(pathname) {
    return pathname === '/' || 
           pathname === '/status' || 
           pathname === '/history' || 
           pathname === '/process_scan' || 
           pathname === '/report' ||
           pathname === '/whois';
}

// Message handling for cache management
self.addEventListener('message', event => {
    if (event.data && event.data.type === 'CLEAR_CACHE') {
        event.waitUntil(
            caches.keys().then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => caches.delete(cacheName))
                );
            }).then(() => {
                console.log('All caches cleared');
                event.ports[0].postMessage({ success: true });
            })
        );
    }
});
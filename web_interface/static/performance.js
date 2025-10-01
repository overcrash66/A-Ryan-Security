/**
 * Performance-Optimized JavaScript for A-Ryan Security Application
 * Handles efficient loading, caching, and user interactions
 */

// Performance utilities
const PerformanceUtils = {
    // Debounce function to limit API calls
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // Throttle function for scroll events
    throttle: function(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        }
    },
    
    // Efficient DOM manipulation
    batchDOMUpdates: function(updates) {
        requestAnimationFrame(() => {
            updates.forEach(update => update());
        });
    },
    
    // Lazy loading for images and content
    lazyLoad: function(elements) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const element = entry.target;
                    if (element.dataset.src) {
                        element.src = element.dataset.src;
                        element.removeAttribute('data-src');
                    }
                    observer.unobserve(element);
                }
            });
        });
        
        elements.forEach(el => observer.observe(el));
    }
};

// Optimized API Manager
class OptimizedAPIManager {
    constructor() {
        this.cache = new Map();
        this.pendingRequests = new Map();
        this.batchQueue = [];
        this.batchTimeout = null;
    }
    
    // Intelligent caching with TTL
    async get(url, options = {}) {
        const cacheKey = url + JSON.stringify(options);
        const cached = this.cache.get(cacheKey);
        
        if (cached && Date.now() - cached.timestamp < (options.ttl || 300000)) {
            console.log(`Cache HIT: ${url}`);
            return cached.data;
        }
        
        // Prevent duplicate requests
        if (this.pendingRequests.has(cacheKey)) {
            return this.pendingRequests.get(cacheKey);
        }
        
        const request = this.fetchData(url, options);
        this.pendingRequests.set(cacheKey, request);
        
        try {
            const data = await request;
            this.cache.set(cacheKey, {
                data: data,
                timestamp: Date.now()
            });
            return data;
        } finally {
            this.pendingRequests.delete(cacheKey);
        }
    }
    
    async fetchData(url, options) {
        const response = await fetch(url, {
            method: options.method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
    }
    
    // Batch multiple API calls
    batchCall(urls) {
        return Promise.all(urls.map(url => this.get(url)));
    }
    
    // Clear cache
    clearCache() {
        this.cache.clear();
    }
    
    // Get cache stats
    getCacheStats() {
        return {
            size: this.cache.size,
            pendingRequests: this.pendingRequests.size
        };
    }
}

// Optimized Page Loaders
class OptimizedStatusLoader {
    constructor() {
        this.apiManager = new OptimizedAPIManager();
        this.isLoading = false;
    }
    
    async loadStatusData() {
        if (this.isLoading) return;
        this.isLoading = true;
        
        try {
            // Use batch API for better performance
            const result = await this.apiManager.get('/api/status/batch', { ttl: 60000 });
            
            if (result.status === 'success') {
                this.updateStatusDisplay(result.data);
            } else {
                console.error('Batch status load failed:', result.error);
                // Fallback to individual calls if batch fails
                await this.loadIndividualData();
            }
        } catch (error) {
            console.error('Error loading status data:', error);
            await this.loadIndividualData();
        } finally {
            this.isLoading = false;
        }
    }
    
    async loadIndividualData() {
        // Fallback to individual API calls
        const endpoints = [
            '/api/status/av',
            '/api/status/fw',
            '/api/status/net',
            '/api/status/traffic'
        ];
        
        try {
            const results = await this.apiManager.batchCall(endpoints);
            console.log('Individual API calls completed:', results);
        } catch (error) {
            console.error('Individual API calls failed:', error);
        }
    }
    
    updateStatusDisplay(data) {
        // Efficiently update DOM elements
        PerformanceUtils.batchDOMUpdates([
            () => this.updateCard('av', data.av),
            () => this.updateCard('fw', data.fw),
            () => this.updateCard('net', data.net),
            () => this.updateTraffic(data.traffic),
            () => this.updateAIAdvice(data.advice)
        ]);
    }
    
    updateCard(type, data) {
        // Efficient DOM updates without full page reload
        const card = document.querySelector(`[data-card="${type}"]`);
        if (card && data) {
            const content = card.querySelector('.status-content');
            if (content) {
                content.innerHTML = this.formatCardContent(data);
            }
        }
    }
    
    updateTraffic(traffic) {
        const trafficCard = document.querySelector('[data-card="traffic"]');
        if (trafficCard && traffic) {
            const content = trafficCard.querySelector('.status-content');
            if (content) {
                content.innerHTML = traffic.map(item => 
                    `<p class="traffic-item">📡 ${item}</p>`
                ).join('');
            }
        }
    }
    
    updateAIAdvice(advice) {
        const aiSection = document.querySelector('.ai-analysis');
        if (aiSection && advice) {
            aiSection.innerHTML = advice.replace(/\n/g, '<br>');
        }
    }
    
    formatCardContent(data) {
        if (data.error) {
            return `<p class="error-message">⚠️ Error: ${data.error}</p>`;
        } else if (typeof data === 'string') {
            return `<p class="status-message">✅ ${data}</p>`;
        } else {
            return `<p class="warning-message">⚠️ No data available</p>`;
        }
    }
}

class OptimizedHistoryLoader {
    constructor() {
        this.apiManager = new OptimizedAPIManager();
        this.isLoading = false;
    }
    
    async loadHistoryData() {
        if (this.isLoading) return;
        this.isLoading = true;
        
        try {
            // Use batch API for better performance
            const result = await this.apiManager.get('/api/history/batch', { ttl: 120000 });
            
            if (result.status === 'success') {
                this.updateHistoryDisplay(result.data);
            } else {
                console.error('Batch history load failed:', result.error);
            }
        } catch (error) {
            console.error('Error loading history data:', error);
        } finally {
            this.isLoading = false;
        }
    }
    
    updateHistoryDisplay(data) {
        // Efficiently update DOM elements
        PerformanceUtils.batchDOMUpdates([
            () => this.updateLogs(data.logs),
            () => this.updateIssues(data.issues),
            () => this.updatePredictions(data.predictions),
            () => this.updateScanHistory(data.scan_history)
        ]);
    }
    
    updateLogs(logs) {
        const logsContainer = document.querySelector('.logs-container');
        if (logsContainer && logs) {
            // Use document fragment for efficient DOM manipulation
            const fragment = document.createDocumentFragment();
            logs.forEach(log => {
                const logElement = this.createLogElement(log);
                fragment.appendChild(logElement);
            });
            logsContainer.innerHTML = '';
            logsContainer.appendChild(fragment);
        }
    }
    
    createLogElement(log) {
        const div = document.createElement('div');
        div.className = `log-entry ${log.level.toLowerCase()}`;
        div.innerHTML = `
            <div class="log-timestamp">${new Date(log.timestamp).toLocaleString()}</div>
            <div class="log-level">
                <span class="level-badge ${log.level.toLowerCase()}">${log.level}</span>
            </div>
            <div class="log-message">${log.message}</div>
        `;
        return div;
    }
    
    updateIssues(issues) {
        // Similar efficient update for issues
        console.log('Issues updated:', issues.length);
    }
    
    updatePredictions(predictions) {
        const predictionsElement = document.querySelector('.prediction-text');
        if (predictionsElement && predictions) {
            predictionsElement.innerHTML = predictions.replace(/\n/g, '<br>');
        }
    }
    
    updateScanHistory(scanHistory) {
        // Similar efficient update for scan history
        console.log('Scan history updated:', scanHistory.length);
    }
}

// Global instances
window.optimizedAPIManager = new OptimizedAPIManager();
window.optimizedStatusLoader = null;
window.optimizedHistoryLoader = null;

// Performance monitoring
const performanceMetrics = {
    startTime: performance.now(),
    
    markMilestone: function(name) {
        const time = performance.now();
        console.log(`Performance Milestone [${name}]: ${(time - this.startTime).toFixed(2)}ms`);
        
        // Send to server for monitoring
        if (navigator.sendBeacon) {
            navigator.sendBeacon('/api/performance/metric', JSON.stringify({
                milestone: name,
                time: time - this.startTime,
                url: window.location.pathname
            }));
        }
    },
    
    measurePageLoad: function() {
        window.addEventListener('load', () => {
            const loadTime = performance.now() - this.startTime;
            console.log(`Total Page Load Time: ${loadTime.toFixed(2)}ms`);
            
            // Log performance metrics
            const navigation = performance.getEntriesByType('navigation')[0];
            if (navigation) {
                console.log('Performance Metrics:', {
                    'DNS Lookup': navigation.domainLookupEnd - navigation.domainLookupStart,
                    'TCP Connect': navigation.connectEnd - navigation.connectStart,
                    'Request': navigation.responseStart - navigation.requestStart,
                    'Response': navigation.responseEnd - navigation.responseStart,
                    'DOM Processing': navigation.domContentLoadedEventEnd - navigation.responseEnd,
                    'Total Load Time': navigation.loadEventEnd - navigation.navigationStart
                });
            }
        });
    }
};

// Initialize performance monitoring
performanceMetrics.measurePageLoad();

// Optimized initialization
document.addEventListener('DOMContentLoaded', function() {
    performanceMetrics.markMilestone('DOM Ready');
    
    // Initialize optimized loaders based on page
    const path = window.location.pathname;
    
    if (path === '/status') {
        window.optimizedStatusLoader = new OptimizedStatusLoader();
        performanceMetrics.markMilestone('Status Loader Initialized');
    } else if (path === '/history') {
        window.optimizedHistoryLoader = new OptimizedHistoryLoader();
        performanceMetrics.markMilestone('History Loader Initialized');
    }
    
    // Lazy load non-critical images
    const lazyImages = document.querySelectorAll('img[data-src]');
    if (lazyImages.length > 0) {
        PerformanceUtils.lazyLoad(lazyImages);
    }
});

// Optimized refresh functions
window.optimizedRefreshStatus = PerformanceUtils.debounce(function() {
    if (window.optimizedStatusLoader) {
        window.optimizedStatusLoader.loadStatusData();
    }
}, 1000);

window.optimizedRefreshHistory = PerformanceUtils.debounce(function() {
    if (window.optimizedHistoryLoader) {
        window.optimizedHistoryLoader.loadHistoryData();
    }
}, 1000);

// Service Worker registration for caching (if supported)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/static/sw.js')
            .then(registration => {
                console.log('ServiceWorker registered successfully');
            })
            .catch(error => {
                console.log('ServiceWorker registration failed');
            });
    });
}

// Performance monitoring API
window.performanceAPI = {
    getMetrics: () => performanceMetrics,
    getCacheStats: () => window.optimizedAPIManager.getCacheStats(),
    clearCache: () => window.optimizedAPIManager.clearCache()
};
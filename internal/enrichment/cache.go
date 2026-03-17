package enrichment

import (
	"sync"
	"time"

	"github.com/freman/dmarcer/internal/models"
)

type cacheEntry struct {
	info      models.IPSourceInfo
	fetchedAt time.Time
}

// ipCache is a thread-safe bounded LRU cache.
type ipCache struct {
	mu      sync.Mutex
	maxSize int
	ttl     time.Duration
	entries map[string]*cacheEntry
	order   []string // LRU order, oldest first
}

func newIPCache(maxSize int, ttl time.Duration) *ipCache {
	return &ipCache{
		maxSize: maxSize,
		ttl:     ttl,
		entries: make(map[string]*cacheEntry),
		order:   make([]string, 0, maxSize),
	}
}

// get returns the cached entry if present and not expired.
func (c *ipCache) get(ip string) (models.IPSourceInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[ip]
	if !ok {
		return models.IPSourceInfo{}, false
	}

	if time.Since(entry.fetchedAt) > c.ttl {
		// Expired - remove it.
		delete(c.entries, ip)
		c.removeFromOrder(ip)

		return models.IPSourceInfo{}, false
	}

	// Move to end (most recently used).
	c.removeFromOrder(ip)
	c.order = append(c.order, ip)

	return entry.info, true
}

// set stores an entry, evicting the oldest if at capacity.
func (c *ipCache) set(ip string, info models.IPSourceInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[ip]; exists {
		// Update existing entry and move to end.
		c.entries[ip] = &cacheEntry{info: info, fetchedAt: time.Now()}
		c.removeFromOrder(ip)
		c.order = append(c.order, ip)

		return
	}

	// Evict oldest entries until we are under capacity.
	for len(c.entries) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}

	c.entries[ip] = &cacheEntry{info: info, fetchedAt: time.Now()}
	c.order = append(c.order, ip)
}

// flush clears all cached entries.
func (c *ipCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
	c.order = c.order[:0]
}

// removeFromOrder removes ip from c.order without holding the lock (caller must hold it).
func (c *ipCache) removeFromOrder(ip string) {
	for i, v := range c.order {
		if v == ip {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

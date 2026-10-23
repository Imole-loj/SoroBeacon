package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// signingKey represents a single active signing key for a webhook channel.
type signingKey struct {
	// ID is a unique key identifier (generated server-side).
	ID string `json:"id" db:"id"`
	// Key is the secret key material; never returned in responses.
	Key []byte `json:"-" db:"key"`
	// CreatedAt is when this key was first created.
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	// IsActive reports whether this key is in the active set.
	IsActive bool `json:"is_active" db:"is_active"`
	// IsExpired reports whether this key has passed its expiry time.
	IsExpired bool `json:"is_expired" db:"is_expired"`
	// ExpiryTime, if set, is when this key expires and is no longer used
	// for signing new payloads. If zero, the key never auto-expires.
	ExpiryTime time.Time `json:"expiry_time" db:"expiry_time"`
}

// KeyTable manages per-channel active signing keys.
type KeyTable struct {
	mu       sync.Mutex
	channels map[string]keyMap // URL -> keyMap
}

type keyMap map[string]*signingKey // keyID -> key

// NewKeyTable returns an empty key table.
func NewKeyTable() *KeyTable {
	return &KeyTable{channels: make(map[string]keyMap)}
}

// AddKey adds a new signing key for a channel identified by its webhook URL.
// The key is stored encrypted at rest (the existing crypto path handles this).
// If a key with the same ID already exists, it is replaced.
// The new key is immediately active; the previous active key (if any) remains
// active until an explicit rotation step.
func (kt *KeyTable) AddKey(url string, key []byte) (*signingKey, error) {
	kt.mu.Lock()
	defer kt.mu.Unlock()

	if kt.channels[url] == nil {
		kt.channels[url] = make(keyMap)
	}

	id := fmt.Sprintf("key-%d", time.Now().UnixNano()+rand.Int63())
	k := &signingKey{
		ID:        id,
		Key:       key,
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	kt.channels[url][id] = k
	return k, nil
}

// GetActiveKeys returns all active (non-expired) signing keys for a channel.
// The returned keys are sorted by created_at ascending so the oldest active
// key is first. This is useful for rotation procedures where receivers need
// to know the full set of valid keys.
func (kt *KeyTable) GetActiveKeys(url string) []*signingKey {
	kt.mu.Lock()
	defer kt.mu.Unlock()

	keys := kt.channels[url]
	if keys == nil {
		return nil
	}

	var active []*signingKey
	for _, k := range keys {
		if k.IsActive && !k.IsExpired {
			active = append(active, k)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].CreatedAt.Before(active[j].CreatedAt)
	})
	return active
}

// GetKey returns the signing key with the given ID for a channel, or nil if not found.
func (kt *KeyTable) GetKey(url, keyID string) *signingKey {
	kt.mu.Lock()
	defer kt.mu.Unlock()

	keys := kt.channels[url]
	if keys == nil {
		return nil
	}
	return keys[keyID]
}

// RotateKey marks the key with the given ID as expired and makes it inactive.
// It returns the key that was rotated, so the caller can record the rotation.
// The previous key (if any) remains active for backwards compatibility.
// After rotation, the new key (just added via AddKey) becomes the primary
// signing key, and the rotated key is retained in the active set but marked
// as expired so receivers that have not yet switched can still verify old deliveries.
func (kt *KeyTable) RotateKey(url, keyID string) (*signingKey, error) {
	kt.mu.Lock()
	defer kt.mu.Unlock()

	keys := kt.channels[url]
	if keys == nil {
		return nil, fmt.Errorf("no keys configured for URL %s", url)
	}

	k, ok := keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %s not found for URL %s", keyID, url)
	}

	k.IsActive = false
	k.IsExpired = true
	k.CreatedAt = time.Time{} // clear, it's expired now

	return k, nil
}

// Sign computes the HMAC-SHA256 signature of a canonical string using a given key.
// The canonical string is "timestamp.rawBody" (timestamp dotted with raw body).
func Sign(key []byte, timestamp string, rawBody []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks whether the given signature is valid for the provided
// timestamp and raw body under any of the active keys for the channel.
// It also supports the "previous" signature header for rotation scenarios.
//
// Returns the key ID that verified the signature, or "" if no key matched.
// If previous is true, it also checks the previous signature header.
func (kt *KeyTable) VerifySignature(url, timestamp string, rawBody []byte, signature, previousSignature string) (string, bool) {
	kt.mu.Lock()
	defer kt.mu.Unlock()

	keys := kt.channels[url]
	if keys == nil {
		return "", false
	}

	// Check current active keys
	for _, k := range keys {
		if !k.IsActive || k.IsExpired {
			continue
		}
		sig := Sign(k.Key, timestamp, rawBody)
		if hmac.Equal([]byte(sig), []byte(signature)) {
			return k.ID, true
		}
	}

	// Check previous keys (for rotation)
	if previousSignature != "" {
		for _, k := range keys {
			if k.ID == "" || k.IsActive || !k.IsExpired {
				continue
			}
			sig := Sign(k.Key, timestamp, rawBody)
			if hmac.Equal([]byte(sig), []byte(previousSignature)) {
				return k.ID, true
			}
		}
	}

	return "", false
}

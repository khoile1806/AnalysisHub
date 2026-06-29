package oob

import (
	"sync"

	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/models"
)

// Hub is a lightweight SSE pub/sub broker keyed on OobClient ID.
// When a new interaction arrives (via the webhook or the OOB server), the
// handler calls Publish; any active StreamOobInteractions SSE connection
// subscribed to that client receives the event without polling.
type Hub struct {
	mu   sync.RWMutex
	subs map[uuid.UUID][]chan models.OobInteraction
}

// NewHub returns a ready-to-use Hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[uuid.UUID][]chan models.OobInteraction)}
}

// Subscribe returns a channel that will receive interactions for clientID.
// The caller must eventually call Unsubscribe to avoid a leak.
func (h *Hub) Subscribe(clientID uuid.UUID) chan models.OobInteraction {
	ch := make(chan models.OobInteraction, 16)
	h.mu.Lock()
	h.subs[clientID] = append(h.subs[clientID], ch)
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from clientID's subscriber list and closes it.
func (h *Hub) Unsubscribe(clientID uuid.UUID, ch chan models.OobInteraction) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.subs[clientID]
	for i, c := range list {
		if c == ch {
			h.subs[clientID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(h.subs[clientID]) == 0 {
		delete(h.subs, clientID)
	}
	close(ch)
}

// Publish sends in to all subscribers of clientID (non-blocking: slow
// subscribers are skipped but not kicked).
func (h *Hub) Publish(clientID uuid.UUID, in models.OobInteraction) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs[clientID] {
		select {
		case ch <- in:
		default:
		}
	}
}

// SubscriberCount returns the number of active SSE connections for clientID.
func (h *Hub) SubscriberCount(clientID uuid.UUID) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[clientID])
}

package ws

import (
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 4 * 1024 * 1024 // 4 MB
)

// Client represents a single WebSocket connection from a remote agent.
type Client struct {
	AgentID string

	hub  *Hub
	conn *websocket.Conn

	// Buffered channel of outbound messages destined for the agent.
	send chan []byte

	// OnRegister is called when the agent sends its "register" message.
	// Parameters: hostname, os, ip.
	OnRegister func(hostname, os, ip string)

	// OnArtifact is called when the agent signals an artifact upload.
	OnArtifact func(jobID, filename string, size int64)

	// OnResourceReport is called when the agent sends a resource_report message
	// containing CPU/RAM/Disk telemetry.
	OnResourceReport func(cpu float64, memUsed, memTotal int64, diskUsed, diskTotal float64)
}

// NewClient creates a Client bound to the given hub and WebSocket connection.
// agentID must be set before calling Start.
func NewClient(hub *Hub, conn *websocket.Conn, agentID string) *Client {
	return &Client{
		AgentID: agentID,
		hub:     hub,
		conn:    conn,
		send:    make(chan []byte, 256),
	}
}

// Start launches the read and write pumps and registers the client with the hub.
// It blocks until the connection is closed (call from a goroutine).
func (c *Client) Start() {
	c.hub.Register <- c

	go c.writePump()
	c.readPump() // blocks
}

// readPump reads messages from the WebSocket connection and forwards them to the hub.
// It runs in the calling goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.Unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[client] read error for agent %s: %v", c.AgentID, err)
			}
			break
		}
		// Reset read deadline on every received message so active agents that
		// send realtime_data every 3s are never dropped by the idle timer.
		c.conn.SetReadDeadline(time.Now().Add(pongWait))

		// Handle "register" messages locally so we can update AgentID / call hook.
		var probe struct {
			Type string `json:"type"`
		}
		if jsonErr := json.Unmarshal(data, &probe); jsonErr == nil {
			if probe.Type == "register" {
				var reg AgentMessage
				if jsonErr2 := json.Unmarshal(data, &reg); jsonErr2 == nil {
					// Update AgentID if provided in the register message.
					if reg.AgentID != "" {
						c.AgentID = reg.AgentID
						// Re-register with the hub under the correct ID.
						c.hub.Register <- c
					}
					if c.OnRegister != nil {
						c.OnRegister(reg.Hostname, reg.OS, reg.IP)
					}
					continue
				}
			} else if probe.Type == "artifact" {
				var art AgentMessage
				if jsonErr2 := json.Unmarshal(data, &art); jsonErr2 == nil && c.OnArtifact != nil {
					c.OnArtifact(art.JobID, art.Filename, art.Size)
					continue
				}
			} else if probe.Type == "resource_report" {
				var res AgentMessage
				if jsonErr2 := json.Unmarshal(data, &res); jsonErr2 == nil && c.OnResourceReport != nil {
					c.OnResourceReport(res.CPUPercent, res.MemUsedMB, res.MemTotalMB, res.DiskUsedGB, res.DiskTotalGB)
					continue
				}
			}
		}

		// Forward all other messages (output, pong, etc.) to the hub.
		c.hub.receiveFromAgent(c, data)
	}
}

// writePump pumps messages from the send channel to the WebSocket connection.
// It runs in its own goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("[client] write error for agent %s: %v", c.AgentID, err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			// Send a JSON ping so agents can respond with pong.
			ping, _ := json.Marshal(AgentCommand{Type: "ping"})
			if err := c.conn.WriteMessage(websocket.TextMessage, ping); err != nil {
				return
			}
		}
	}
}

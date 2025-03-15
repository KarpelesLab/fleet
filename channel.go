// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/KarpelesLab/goupd"
)

// Mutex to prevent concurrent channel update operations
var channelUpdateLock sync.Mutex

// SwitchChannel signals all nodes in the fleet to switch to the given update channel.
// This allows coordinated switching between different versions or release tracks
// (e.g., stable, beta, development) across the entire fleet.
//
// The change is propagated to all nodes through the distributed database. All nodes
// will detect the change and update their channel accordingly.
//
// Warning: Attempting to switch to a non-existing channel will trigger errors
// across the fleet, as each node tries to switch to an invalid channel.
//
// Parameters:
//   - channel: The update channel to switch to
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (a *Agent) SwitchChannel(channel string) error {
	// Store the channel in the global bucket with the current timestamp
	// This will be synchronized across all peers
	return a.feedDbSetBC([]byte("global"), []byte("channel"), []byte(channel), DbNow())
}

// channelSet initializes the update channel value in the database.
// This is called during Agent startup to ensure the channel is properly set,
// and to trigger an update if the current channel differs from the stored one.
func (a *Agent) channelSet() {
	// Try to get existing channel from the database
	v, err := a.dbSimpleGet([]byte("global"), []byte("channel"))
	if err == nil {
		// Channel exists in the database
		channel := string(v)
		if channel != goupd.CHANNEL {
			// We're on a different channel than what's specified in the DB
			// Schedule an update to match the DB value
			go a.performChannelUpdateLater()
		}
		return
	}

	// Channel doesn't exist in the database, initialize it with the current value
	// We use a timestamp from the past (1970) so this will be overwritten if
	// any other node has already set a channel value
	a.feedDbSet([]byte("global"), []byte("channel"), []byte(goupd.CHANNEL),
		DbStamp(time.Unix(0, 0))) // Jan 1st 1970
}

// notifyChannelChange is called when the channel value changes in the database.
// This triggers an update to match the new channel if needed.
//
// Parameters:
//   - channel: The new channel value from the database
func (a *Agent) notifyChannelChange(channel string) {
	// If we're already on this channel, nothing to do
	if goupd.CHANNEL == channel {
		return
	}

	// Schedule an update to the new channel
	go a.performChannelUpdateLater()
}

// performChannelUpdateLater waits for a short period and then performs
// the actual channel update. This delay ensures the database has time
// to synchronize across peers before taking action.
func (a *Agent) performChannelUpdateLater() {
	// Wait for the database to synchronize
	time.Sleep(15 * time.Second)

	// Ensure only one update happens at a time
	channelUpdateLock.Lock()
	defer channelUpdateLock.Unlock()

	// Get the current channel from the database
	v, err := a.dbSimpleGet([]byte("global"), []byte("channel"))
	if err != nil {
		slog.Debug(fmt.Sprintf("fleet: failed to check current value for global:channel: %s", err),
			"event", "fleet:chanel:missing")
		return
	}

	// Parse and validate the channel
	channel := string(v)
	if channel == "" {
		channel = "master" // Default channel if empty
	}

	// If we're already on this channel, nothing to do
	if channel == goupd.CHANNEL {
		return
	}

	// Perform the actual channel switch
	// This will typically trigger a software update
	goupd.SwitchChannel(channel)
}

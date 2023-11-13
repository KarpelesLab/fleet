package fleet

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/KarpelesLab/goupd"
)

var channelUpdateLock sync.Mutex

// SwitchChannel will signal the whole fleet to switch to the given channel for
// the currently running software. This can be used to switch between stable
// and beta versions and the like. Attempting to switch to a non-existing
// channel will trigger errors across the fleet.
func (a *Agent) SwitchChannel(channel string) error {
	// let's switch the running channel of the whole fleet
	return a.feedDbSetBC([]byte("global"), []byte("channel"), []byte(channel), DbNow())
}

func (a *Agent) channelSet() {
	// ensure db contains "channel" value
	v, err := a.dbSimpleGet([]byte("global"), []byte("channel"))
	if err == nil {
		channel := string(v)
		if channel != goupd.CHANNEL {
			go a.performChannelUpdateLater()
		}
		return
	}

	// set a value with a DbStamp in the past in order to be overwritten if there is something better out there
	// we do not broadcast in order to avoid weird stuff from happening
	a.feedDbSet([]byte("global"), []byte("channel"), []byte(goupd.CHANNEL), DbStamp(time.Unix(0, 0))) // Jan 1st 1970
}

func (a *Agent) notifyChannelChange(channel string) {
	if goupd.CHANNEL == channel {
		return
	}

	// perform update later
	go a.performChannelUpdateLater()
}

func (a *Agent) performChannelUpdateLater() {
	// this is called when we probably need to update channel, but should wait for the db to sync first just in case
	time.Sleep(15 * time.Second)

	channelUpdateLock.Lock()
	defer channelUpdateLock.Unlock()

	v, err := a.dbSimpleGet([]byte("global"), []byte("channel"))
	if err != nil {
		slog.Debug(fmt.Sprintf("fleet: failed to check current value for global:channel: %s", err), "event", "fleet:chanel:missing")
		return
	}
	channel := string(v)
	if channel == goupd.CHANNEL {
		// turns out we don't have to do anything
		return
	}

	// let's perform the update
	goupd.SwitchChannel(channel)
}

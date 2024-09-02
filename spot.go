package fleet

import (
	"fmt"
	"log/slog"
	"path"
	"runtime/debug"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotlib"
)

func (a *Agent) initSpot() {
	k, err := a.getLocalKey()
	if err != nil {
		slog.Debug(fmt.Sprintf("failed to fetch local key: %s", err), "event", "fleet:spot:key_fail")
		return
	}
	kc := cryptutil.NewKeychain()
	if tk, ok := k.(interface{ Keychain() *cryptutil.Keychain }); ok {
		kc = tk.Keychain()
	} else {
		kc.AddKey(k)
	}
	meta := map[string]string{"agent": "go-fleet"}
	if info, ok := debug.ReadBuildInfo(); ok {
		meta["project"] = path.Base(info.Path)
	}
	a.spot, err = spotlib.New(kc, meta)
	if err != nil {
		slog.Debug(fmt.Sprintf("failed to init spot: %s", err), "event", "fleet:spot:init_fail")
	}
}

func (a *Agent) shutdownSpot() {
	if a.spot != nil {
		a.spot.Close()
		a.spot = nil
	}
}

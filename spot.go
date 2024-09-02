package fleet

import (
	"fmt"
	"log/slog"

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
	}
	a.spot, err = spotlib.New(kc)
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

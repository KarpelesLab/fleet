// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/KarpelesLab/goupd"
)

// The fleet database system provides a synchronized key-value store across all peers.
// Data is stored in-memory and persisted to a YAML file.
//
// Key features:
// - Data is versioned with nanosecond timestamps
// - Updates are automatically broadcast to all peers
// - Conflict resolution based on timestamps
// - Automatic synchronization on connection establishment
// - Watch callbacks for database changes
//
// Database buckets:
// - "app": Application data, available to users
// - "fleet": Fleet internal configuration data
// - "local": Local-only data that isn't synchronized
// - "global": System-wide settings
// - "version": Metadata about record versions
// - "vlog": Change log for record updates

// DbWatchCallback is a function type for callbacks triggered on database changes.
// It receives the key that changed and its new value (or nil if deleted).
type DbWatchCallback func(string, []byte)

// initDb initializes the agent's database.
// This creates an in-memory database backed by a YAML file.
// If an existing bbolt database is found, it will be migrated to YAML format.
func (a *Agent) initDb() {
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	d = filepath.Join(d, goupd.PROJECT_NAME)
	EnsureDir(d)

	yamlPath := filepath.Join(d, "fleet.yaml")
	boltPath := filepath.Join(d, "fleet.db")

	a.db = newYamlDb(yamlPath)

	// Check if YAML file exists
	if _, err := os.Stat(yamlPath); err == nil {
		// YAML file exists, load it
		if err := a.db.load(); err != nil {
			panic(err)
		}
		return
	}

	// Check if bbolt file exists for migration
	if _, err := os.Stat(boltPath); err == nil {
		// Migrate from bbolt to YAML
		if err := a.db.migrateFromBolt(boltPath); err != nil {
			panic(err)
		}
		return
	}

	// Neither file exists - start with empty database
}

// DbGet retrieves a value from the shared fleet database.
// This is the primary method for applications to get data from the synchronized database.
//
// Parameters:
//   - key: The key to retrieve
//
// Returns:
//   - The value as a byte slice
//   - An error if the key doesn't exist or if the operation fails
func (a *Agent) DbGet(key string) ([]byte, error) {
	v, err := a.dbSimpleGet([]byte("app"), []byte(key))
	return v, err
}

// DbSet stores a value in the shared fleet database.
// This value will be automatically synchronized to all peers in the fleet.
//
// Parameters:
//   - key: The key to store the value under
//   - value: The data to store
//
// Returns:
//   - An error if the operation fails
func (a *Agent) DbSet(key string, value []byte) error {
	return a.feedDbSetBC([]byte("app"), []byte(key), value, DbNow())
}

// DbDelete removes a value from the shared fleet database.
// This deletion will be propagated to all peers in the fleet.
//
// Parameters:
//   - key: The key to delete
//
// Returns:
//   - An error if the operation fails
func (a *Agent) DbDelete(key string) error {
	return a.feedDbSetBC([]byte("app"), []byte(key), nil, DbNow())
}

// DbWatch registers a callback function to be called when a key is updated.
// The callback will be triggered whenever the specified key changes in the database.
//
// Special features:
// - Using "*" as the key will trigger the callback for all key changes
// - If the value in the callback is nil, it indicates the key was deleted
//
// Parameters:
//   - key: The key to watch, or "*" for all keys
//   - cb: Callback function that receives the key and its new value
func (a *Agent) DbWatch(key string, cb func(string, []byte)) {
	a.dbWatchLock.Lock()
	defer a.dbWatchLock.Unlock()

	// Add this callback to the list of watchers for this key
	a.dbWatch[key] = append(a.dbWatch[key], cb)
}

func (a *Agent) getWatchTriggerCallback(keys ...string) (res []DbWatchCallback) {
	a.dbWatchLock.RLock()
	defer a.dbWatchLock.RUnlock()

	for _, k := range keys {
		if cb, ok := a.dbWatch[k]; ok {
			res = append(res, cb...)
		}
	}
	return
}

func (a *Agent) dbWatchTrigger(bucket, key string, val []byte) {
	switch bucket {
	case "global":
		switch key {
		case "channel":
			a.notifyChannelChange(string(val))
		}
	case "app":
		for _, cb := range a.getWatchTriggerCallback(key, "*") {
			cb(key, val)
		}
	}
}

func (a *Agent) feedDbSetBC(bucket, key, val []byte, v DbStamp) error {
	if err := a.feedDbSet(bucket, key, val, v); err != nil {
		return err
	}
	a.broadcastDbRecord(context.Background(), bucket, key, val, v)
	return nil
}

func (a *Agent) needDbEntry(bucket, key []byte, v DbStamp) bool {
	if string(bucket) == "local" || string(bucket) == "fleet" {
		// bucket "local" cannot be replicated
		return false
	}
	// compute global key (bucket + NUL + key)
	fk := append(append(bucket, 0), key...)
	// check version
	curV, err := a.dbSimpleGet([]byte("version"), fk)
	if err != nil {
		return true // yes, need
	}
	var curVT DbStamp
	err = curVT.UnmarshalBinary(curV)
	if err != nil {
		return false
	}

	if bytes.HasSuffix(key, []byte{'!'}) {
		return curVT.After(v)
	}

	// if "v" is after our version, we need it
	return v.After(curVT)
}

func (a *Agent) feedDbSet(bucket, key, val []byte, v DbStamp) error {
	if string(bucket) == "local" || string(bucket) == "fleet" {
		// bucket "local" cannot be replicated
		return nil
	}

	// compute global key (bucket + NUL + key)
	fk := append(append(bucket, 0), key...)
	// check version
	curV, err := a.dbSimpleGet([]byte("version"), fk)
	if err == nil && len(curV) > 0 {
		// decode curV
		var curVT DbStamp
		err = curVT.UnmarshalBinary(curV)
		if err != nil {
			return err
		}
		// compare with v
		if bytes.HasSuffix(key, []byte{'!'}) {
			if !curVT.After(v) {
				return nil
			}
		} else {
			if !v.After(curVT) {
				// no need for update, we already have the latest version
				return nil
			}
		}
	}

	// update version bucket
	vBin, _ := v.MarshalBinary()
	if err := a.db.setWithStamp([]byte("version"), fk, vBin, v); err != nil {
		return err
	}

	// update vlog
	a.db.updateVlog(bucket, key, v)

	// update actual data
	if err := a.db.setWithStamp(bucket, key, val, v); err != nil {
		return err
	}

	go a.dbWatchTrigger(string(bucket), string(key), val)
	return nil
}

func (a *Agent) dbGetVersion(bucket, key []byte) (val []byte, stamp DbStamp, err error) {
	if string(bucket) == "local" || string(bucket) == "fleet" {
		// bucket "local" cannot be replicated
		err = fs.ErrNotExist
		return
	}
	return a.db.getVersion(bucket, key)
}

func (a *Agent) databasePacket() *PacketDbVersions {
	p := &PacketDbVersions{}

	for k, v := range a.DbKeys([]byte("version"), nil) {
		// version global key (bucket + NUL + key)
		k2 := slices.Clone(k)
		k3 := bytes.SplitN(k2, []byte{0}, 2)
		if len(k3) == 2 {
			if string(k3[0]) == "local" || string(k3[0]) == "fleet" {
				continue
			}
			stamp := DbStamp{}
			stamp.UnmarshalBinary(v)
			p.Info = append(p.Info, &PacketDbVersionsEntry{Stamp: stamp, Bucket: k3[0], Key: k3[1]})
		}
	}
	return p
}

// internal setter
func (a *Agent) dbSimpleSet(bucket, key, val []byte) error {
	return a.db.set(bucket, key, val)
}

// internal delete
func (a *Agent) dbSimpleDel(bucket []byte, keys ...[]byte) error {
	return a.db.del(bucket, keys...)
}

// internal getter
func (a *Agent) dbSimpleGet(bucket, key []byte) ([]byte, error) {
	return a.db.get(bucket, key)
}

// dbFleetLoad is similar to dbFleetGet except it always attempt to load data from getFile first
func (a *Agent) dbFleetLoad(keyname string) ([]byte, error) {
	// attempt to locate file named a.b for key a:b
	filename := strings.ReplaceAll(keyname, ":", ".")
	if strings.HasSuffix(filename, ".crt") {
		// replace with .pem
		filename = strings.TrimSuffix(filename, ".crt") + ".pem"
	}

	var data []byte
	err := a.getFile(filename, func(v []byte) error {
		data = v
		return a.dbSimpleSet([]byte("fleet"), []byte(keyname), v)
	})
	if err == nil {
		return data, nil
	}
	return a.dbSimpleGet([]byte("fleet"), []byte(keyname))
}

func (a *Agent) dbFleetGet(keyname string) ([]byte, error) {
	// for example keyname="internal_key:jwt"

	data, err := a.dbSimpleGet([]byte("fleet"), []byte(keyname))
	if err == nil {
		return data, nil
	}

	// attempt to locate file named a.b for key a:b
	filename := strings.ReplaceAll(keyname, ":", ".")
	if strings.HasSuffix(filename, ".crt") {
		// replace with .pem
		filename = strings.TrimSuffix(filename, ".crt") + ".pem"
	}

	err = a.getFile(filename, func(v []byte) error {
		data = v
		return a.dbSimpleSet([]byte("fleet"), []byte(keyname), v)
	})
	if err == nil {
		return data, nil
	}

	return data, err
}

func (a *Agent) dbFleetDel(keynames ...string) error {
	if len(keynames) == 0 {
		return nil
	}
	// for example keyname="internal_key:jwt"
	keys := make([][]byte, len(keynames))
	for n, keyname := range keynames {
		keys[n] = []byte(keyname)
	}
	return a.dbSimpleDel([]byte("fleet"), keys...)
}

func (a *Agent) DbKeys(bucket, prefix []byte) func(yield func(k, v []byte) bool) {
	return a.db.keys(bucket, prefix)
}

func (a *Agent) shutdownDb() {
	a.db.close()
}

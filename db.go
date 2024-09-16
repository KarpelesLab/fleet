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
	bolt "go.etcd.io/bbolt"
)

// DB is a local db with data versioned & copied across all members of the fleet through the DB endpoint
// each regular DB update is pushed to everyone
// each DB entry has a nanosecond timestamp, if multiple updates of one key are done at the same time they are all kept together
// any node can ask to replay changes done to the db since any point in time, including zero
// timestamp for keys are stored in 2x int64 (second, nanosecond), as bigendian when serialized

type DbWatchCallback func(string, []byte)

func (a *Agent) initDb() {
	// Open the Bolt database located in the config directory
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	d = filepath.Join(d, goupd.PROJECT_NAME)
	EnsureDir(d)
	a.db, err = bolt.Open(filepath.Join(d, "fleet.db"), 0600, nil)
	if err != nil {
		panic(err)
	}
}

// DbGet will get a value from the shared fleet database
func (a *Agent) DbGet(key string) ([]byte, error) {
	v, err := a.dbSimpleGet([]byte("app"), []byte(key))
	return v, err
}

// DbSet will set a value into the shared fleet database
func (a *Agent) DbSet(key string, value []byte) error {
	return a.feedDbSetBC([]byte("app"), []byte(key), value, DbNow())
}

// DbDelete will remove a value from the shared fleet database
func (a *Agent) DbDelete(key string) error {
	return a.feedDbSetBC([]byte("app"), []byte(key), nil, DbNow())
}

// DbWatch will trigger the cb function upon updates of the given key
// Special key "*" covers all keys (can only be one callback for a key)
// If the value is nil, it means it is being deleted
func (a *Agent) DbWatch(key string, cb func(string, []byte)) {
	a.dbWatchLock.Lock()
	defer a.dbWatchLock.Unlock()

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

	// update
	err = a.db.Update(func(tx *bolt.Tx) error {
		vb, err := tx.CreateBucketIfNotExists([]byte("version"))
		if err != nil {
			return err
		}
		vl, err := tx.CreateBucketIfNotExists([]byte("vlog"))
		if err != nil {
			return err
		}
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}

		vBin, _ := v.MarshalBinary()

		err = vb.Put(fk, vBin)
		if err != nil {
			return err
		}
		// remove old entries from vlog
		c := vl.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if bytes.Equal(v, fk) {
				vl.Delete(k) // this delete has no reason to fail, and even if it does it's not really an issue
			}
		}

		// add to vlog
		err = vl.Put(append(vBin, fk...), fk)
		if err != nil {
			return err
		}

		if val == nil {
			return b.Delete(key)
		}

		return b.Put(key, val)
	})
	go a.dbWatchTrigger(string(bucket), string(key), val)
	return err
}

func (a *Agent) dbGetVersion(bucket, key []byte) (val []byte, stamp DbStamp, err error) {
	if string(bucket) == "local" || string(bucket) == "fleet" {
		// bucket "local" cannot be replicated
		err = fs.ErrNotExist
		return
	}
	err = a.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fs.ErrNotExist
		}
		v := b.Get(key)
		if v == nil {
			return fs.ErrNotExist
		}
		val = make([]byte, len(v))
		copy(val, v)

		versionBucket := tx.Bucket([]byte("version"))
		fk := append(append(bucket, 0), key...)
		vers := versionBucket.Get(fk)
		if v == nil {
			// no stamp
			return nil
		}
		return stamp.UnmarshalBinary(vers)
	})
	return
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
	return a.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}
		return b.Put(key, val)
	})
}

// internal delete
func (a *Agent) dbSimpleDel(bucket []byte, keys ...[]byte) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		for _, key := range keys {
			if err := b.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

// internal getter
func (a *Agent) dbSimpleGet(bucket, key []byte) (r []byte, err error) {
	err = a.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fs.ErrNotExist
		}
		v := b.Get(key)
		if v == nil {
			return fs.ErrNotExist
		}
		r = make([]byte, len(v))
		copy(r, v)
		return nil
	})
	return
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
	return func(yield func(k, v []byte) bool) {
		a.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucket)
			if b == nil {
				// no data
				return nil
			}
			c := b.Cursor()
			if prefix != nil {
				k, v := c.Seek(prefix)
				if k == nil {
					// could not seek?
					return nil
				}
				for k != nil && bytes.HasPrefix(k, prefix) {
					if !yield(k[len(prefix):], v) {
						break
					}
					k, v = c.Next()
				}
				return nil
			}
			k, v := c.First()
			for k != nil {
				if !yield(k, v) {
					break
				}
				k, v = c.Next()
			}
			return nil
		})
	}
}

func (a *Agent) shutdownDb() {
	a.db.Close()
}

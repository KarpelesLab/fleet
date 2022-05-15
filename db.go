package fleet

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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

// simple db get for program usage
func (a *Agent) DbGet(key string) ([]byte, error) {
	v, err := a.dbSimpleGet([]byte("app"), []byte(key))
	return v, err
}

// simple db set for program usage
func (a *Agent) DbSet(key string, value []byte) error {
	return a.feedDbSetBC([]byte("app"), []byte(key), value, DbNow())
}

// DbWatch will trigger the cb function upon updates of the given key
// Special key "*" covers all keys (can only be one callback for a key)
func (a *Agent) DbWatch(key string, cb func(string, []byte)) {
	a.dbWatchLock.Lock()
	defer a.dbWatchLock.Unlock()

	a.dbWatch[key] = cb
}

func (a *Agent) dbWatchTrigger(key string, val []byte) {
	a.dbWatchLock.RLock()
	cb1, ok1 := a.dbWatch[key]
	cb2, ok2 := a.dbWatch["*"]
	a.dbWatchLock.RUnlock()

	if ok1 {
		cb1(key, val)
	}
	if ok2 {
		cb2(key, val)
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
		if !v.After(curVT) {
			// no need for update, we already have the latest version
			return nil
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

		return b.Put(key, val)
	})
	go a.dbWatchTrigger(string(key), val)
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
			return os.ErrNotExist
		}
		v := b.Get(key)
		if v == nil {
			return os.ErrNotExist
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

	if c, err := a.NewDbCursor([]byte("version")); err == nil {
		// version global key (bucket + NUL + key)
		defer c.Close()
		k, v := c.First()
		for {
			if k == nil {
				break
			}
			k2 := make([]byte, len(k))
			copy(k2, k)
			k3 := bytes.SplitN(k2, []byte{0}, 2)
			if len(k3) == 2 {
				if string(k3[0]) == "local" || string(k3[0]) == "fleet" {
					continue
				}
				stamp := DbStamp{}
				stamp.UnmarshalBinary(v)
				p.Info = append(p.Info, &PacketDbVersionsEntry{Stamp: stamp, Bucket: k3[0], Key: k3[1]})
			}
			k, v = c.Next()
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
func (a *Agent) dbSimpleDel(bucket, key []byte) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		return b.Delete(key)
	})
}

// internal getter
func (a *Agent) dbSimpleGet(bucket, key []byte) (r []byte, err error) {
	err = a.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return os.ErrNotExist
		}
		v := b.Get(key)
		if v == nil {
			return os.ErrNotExist
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

func (a *Agent) dbFleetDel(keyname string) error {
	// for example keyname="internal_key:jwt"
	return a.dbSimpleDel([]byte("fleet"), []byte(keyname))
}

type DbCursor struct {
	tx     *bolt.Tx
	bucket *bolt.Bucket
	cursor *bolt.Cursor
	pfx    []byte
}

func dbCursorFinalizer(c *DbCursor) {
	c.tx.Rollback()
}

func (a *Agent) NewDbCursor(bucket []byte) (*DbCursor, error) {
	// create a readonly tx and a cursor
	tx, err := a.db.Begin(false)
	if err != nil {
		return nil, err
	}

	r := &DbCursor{tx: tx}
	runtime.SetFinalizer(r, dbCursorFinalizer)

	r.bucket = tx.Bucket(bucket)
	if r.bucket == nil {
		tx.Rollback()
		return nil, os.ErrNotExist
	}

	r.cursor = r.bucket.Cursor()
	return r, nil
}

func (c *DbCursor) Seek(pfx []byte) ([]byte, []byte) {
	c.pfx = pfx
	k, v := c.cursor.Seek(pfx)
	if pfx == nil {
		return k, v
	}
	if k == nil {
		// couldn't seek
		return nil, nil
	}
	if !bytes.HasPrefix(k, pfx) {
		// key not found
		return nil, nil
	}

	return k[len(pfx):], v
}

func (c *DbCursor) First() ([]byte, []byte) {
	c.pfx = nil
	return c.cursor.First()
}

func (c *DbCursor) Last() ([]byte, []byte) {
	c.pfx = nil
	return c.cursor.Last()
}

func (c *DbCursor) Next() ([]byte, []byte) {
	k, v := c.cursor.Next()
	if k == nil {
		return nil, nil
	}
	if c.pfx != nil {
		if !bytes.HasPrefix(k, c.pfx) {
			return nil, nil
		}
		return k[len(c.pfx):], v
	}
	return k, v
}

func (c *DbCursor) Close() error {
	return c.tx.Rollback()
}

func (a *Agent) shutdownDb() {
	a.db.Close()
}

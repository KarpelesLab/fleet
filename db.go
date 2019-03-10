package fleet

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"

	"github.com/boltdb/bolt"
)

// DB is a local db with data versioned & copied across all members of the fleet through the DB endpoint
// each regular DB update is pushed to everyone
// each DB entry has a nanosecond timestamp, if multiple updates of one key are done at the same time they are all kept together
// any node can ask to replay changes done to the db since any point in time, including zero
// timestamp for keys are stored in 2x int64 (second, nanosecond), as bigendian when serialized

var db *bolt.DB

func initDb() {
	// Open the Bolt database located in the config directory
	var err error
	d := GetConfigDir()
	EnsureDir(d)
	db, err = bolt.Open(filepath.Join(d, "fleet.db"), 0600, nil)
	if err != nil {
		panic(err)
	}
}

// simple db get for program usage
func DbGet(key string) (string, error) {
	v, err := dbSimpleGet([]byte("app"), []byte(key))
	return string(v), err
}

// simple db set for program usage
func DbSet(key string, value []byte) error {
	return feedDbSetBC([]byte("app"), []byte(key), value, DbNow())
}

func feedDbSetBC(bucket, key, val []byte, v DbStamp) error {
	if err := feedDbSet(bucket, key, val, v); err != nil {
		return err
	}
	Agent.broadcastDbRecord(bucket, key, val, v)
	return nil
}

func feedDbSet(bucket, key, val []byte, v DbStamp) error {
	if string(bucket) == "local" || string(bucket) == "fleet" {
		// bucket "local" cannot be replicated
		return nil
	}

	// compute global key (bucket + NUL + key)
	fk := append(append(bucket, 0), key...)
	// check version
	curV, err := dbSimpleGet([]byte("version"), fk)
	if err != nil {
		return err
	}
	// decode curV
	if len(curV) > 0 {
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
	return db.Update(func(tx *bolt.Tx) error {
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
}

// internal setter
func dbSimpleSet(bucket, key, val []byte) error {
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}
		return b.Put(key, val)
	})
}

// internal getter
func dbSimpleGet(bucket, key []byte) (r []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
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

type DbCursor struct {
	tx     *bolt.Tx
	bucket *bolt.Bucket
	cursor *bolt.Cursor
	pfx    []byte
}

func dbCursorFinalizer(c *DbCursor) {
	c.tx.Rollback()
}

func NewDbCursor(bucket []byte) (*DbCursor, error) {
	// create a readonly tx and a cursor
	tx, err := db.Begin(false)
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

func shutdownDb() {
	db.Close()
}

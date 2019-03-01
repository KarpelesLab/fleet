package fleet

import (
	"path/filepath"

	"github.com/boltdb/bolt"
)

// DB is a local db with data versioned & copied across all members of the fleet through the DB endpoint
// each DB update is pushed to everyone
// each DB entry has a nanosecond timestamp, if multiple updates of one key are done at the same time they are all kept together
// any node can ask to replay changes done to the db since any point in time, including zero
// timestamp for keys are stored in 2x int64 (second, nanosecond), as bigendian when serialized

var db *bolt.DB

func initDb() {
	// Open the Bolt database located in the config directory
	var err error
	db, err = bolt.Open(filepath.Join(GetConfigDir(), "fleet.db"), 0600, nil)
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
	v := DbNow()

	if err := feedDbSet([]byte("app"), []byte(key), value, v); err != nil {
		return err
	}

	// broadcast
	Agent.broadcastDbRecord([]byte("app"), []byte(key), value, v)
	return nil
}

func feedDbSet(bucket, key, val []byte, v DbStamp) error {
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
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}

		vBin, _ := v.MarshalBinary()

		err = vb.Put(fk, vBin)
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
			return nil
		}
		v := b.Get(key)
		if v != nil {
			r = make([]byte, len(v))
			copy(r, v)
		}
		return nil
	})
	return
}

func shutdownDb() {
	db.Close()
}

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
	// TODO: generate key version, push to other peers
	return dbSimpleSet([]byte("app"), []byte(key), value)
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

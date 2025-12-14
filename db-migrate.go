package fleet

import (
	"log/slog"

	bolt "go.etcd.io/bbolt"
)

// migrateFromBolt migrates data from a bbolt database to the yamlDb.
// The bbolt file is kept but closed after migration.
func (d *yamlDb) migrateFromBolt(boltPath string) error {
	slog.Info("migrating from bbolt to YAML", "bolt_path", boltPath, "yaml_path", d.path)

	// Open bbolt read-only
	boltDb, err := bolt.Open(boltPath, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer boltDb.Close()

	d.Lock()
	defer d.Unlock()

	// Iterate all buckets
	err = boltDb.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(bucketName []byte, b *bolt.Bucket) error {
			bucket := string(bucketName)
			slog.Debug("migrating bucket", "bucket", bucket)

			if d.data[bucket] == nil {
				d.data[bucket] = make(map[string]*dbEntry)
			}

			// Iterate all keys in bucket
			return b.ForEach(func(k, v []byte) error {
				key := string(k)
				val := make([]byte, len(v))
				copy(val, v)

				entry := &dbEntry{value: val}

				// For version bucket, the value is the binary stamp
				// For other buckets, try to get stamp from version bucket
				if bucket == "version" {
					// Value is the stamp itself, stored as binary
					var stamp DbStamp
					if err := stamp.UnmarshalBinary(val); err == nil {
						entry.stamp = stamp
					}
				} else if bucket != "vlog" {
					// Try to get version from version bucket
					versionBucket := tx.Bucket([]byte("version"))
					if versionBucket != nil {
						// Composite key: bucket + NUL + key
						fk := append(append([]byte(bucket), 0), k...)
						if stampBytes := versionBucket.Get(fk); stampBytes != nil {
							var stamp DbStamp
							if err := stamp.UnmarshalBinary(stampBytes); err == nil {
								entry.stamp = stamp
							}
						}
					}
				}

				d.data[bucket][key] = entry
				return nil
			})
		})
	})

	if err != nil {
		return err
	}

	// Log migration stats
	for bucket, entries := range d.data {
		slog.Debug("migrated bucket", "bucket", bucket, "keys", len(entries))
	}

	// Save to YAML
	return d.saveUnlocked()
}

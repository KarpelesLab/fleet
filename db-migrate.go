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

			// Skip version bucket - stamps are now stored with entries
			if bucket == "version" {
				slog.Debug("skipping version bucket (no longer needed)")
				return nil
			}

			// Skip vlog bucket - no longer used
			if bucket == "vlog" {
				slog.Debug("skipping vlog bucket (no longer needed)")
				return nil
			}

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

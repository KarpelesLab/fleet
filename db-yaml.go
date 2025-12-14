package fleet

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// yamlDb is an in-memory database backed by a YAML file.
type yamlDb struct {
	sync.RWMutex
	data map[string]map[string]*dbEntry // bucket -> key -> entry
	path string                         // path to YAML file
}

// dbEntry holds a single database entry with its value and timestamp.
type dbEntry struct {
	value []byte
	stamp DbStamp
}

// yamlBucket represents a bucket in the YAML file.
type yamlBucket map[string]*yamlEntry

// yamlEntry represents an entry in the YAML file.
// Value is stored as string if valid UTF-8, otherwise as base64.
type yamlEntry struct {
	Value string `yaml:"value"`           // String value (plain text or base64-encoded)
	Binary bool   `yaml:"binary,omitempty"` // True if Value is base64-encoded
	Stamp string `yaml:"stamp,omitempty"`
}

// yamlFile is the root structure for the YAML file.
type yamlFile map[string]yamlBucket

// isValidUTF8Text checks if data is valid UTF-8 text suitable for plain YAML storage.
func isValidUTF8Text(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	// Check for control characters that would be problematic in YAML
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// newYamlDb creates a new YAML-backed database.
func newYamlDb(path string) *yamlDb {
	return &yamlDb{
		data: make(map[string]map[string]*dbEntry),
		path: path,
	}
}

// load reads the database from the YAML file.
func (d *yamlDb) load() error {
	d.Lock()
	defer d.Unlock()

	data, err := os.ReadFile(d.path)
	if err != nil {
		return err
	}

	var file yamlFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return err
	}

	for bucket, entries := range file {
		if d.data[bucket] == nil {
			d.data[bucket] = make(map[string]*dbEntry)
		}

		for key, yentry := range entries {
			var val []byte
			if yentry.Binary {
				// Decode base64
				val, err = base64.StdEncoding.DecodeString(yentry.Value)
				if err != nil {
					return fmt.Errorf("failed to decode base64 for %s/%s: %w", bucket, key, err)
				}
			} else {
				val = []byte(yentry.Value)
			}

			entry := &dbEntry{
				value: val,
			}
			if yentry.Stamp != "" {
				entry.stamp = parseStamp(yentry.Stamp)
			}
			d.data[bucket][key] = entry
		}
	}

	return nil
}

// save writes the database to the YAML file atomically.
func (d *yamlDb) save() error {
	d.RLock()
	defer d.RUnlock()

	return d.saveUnlocked()
}

// saveUnlocked saves without acquiring the lock (caller must hold lock).
func (d *yamlDb) saveUnlocked() error {
	file := make(yamlFile)

	// Get sorted bucket names for consistent output
	buckets := make([]string, 0, len(d.data))
	for bucket := range d.data {
		buckets = append(buckets, bucket)
	}
	sort.Strings(buckets)

	for _, bucket := range buckets {
		entries := d.data[bucket]
		if len(entries) == 0 {
			continue
		}

		yb := make(yamlBucket)

		// Get sorted keys for consistent output
		keys := make([]string, 0, len(entries))
		for key := range entries {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			entry := entries[key]
			if entry == nil {
				continue
			}

			yentry := &yamlEntry{}
			if isValidUTF8Text(entry.value) {
				yentry.Value = string(entry.value)
			} else {
				yentry.Value = base64.StdEncoding.EncodeToString(entry.value)
				yentry.Binary = true
			}
			if entry.stamp.After(DbZero()) {
				yentry.Stamp = formatStamp(entry.stamp)
			}
			yb[key] = yentry
		}

		if len(yb) > 0 {
			file[bucket] = yb
		}
	}

	data, err := yaml.Marshal(file)
	if err != nil {
		return err
	}

	// Write to temp file first, then rename for atomicity
	dir := filepath.Dir(d.path)
	tmpFile, err := os.CreateTemp(dir, ".fleet-yaml-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Atomic rename
	if err := os.Rename(tmpPath, d.path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return nil
}

// get retrieves a value from the database.
func (d *yamlDb) get(bucket, key []byte) ([]byte, error) {
	d.RLock()
	defer d.RUnlock()

	b := d.data[string(bucket)]
	if b == nil {
		return nil, fs.ErrNotExist
	}

	entry := b[string(key)]
	if entry == nil || entry.value == nil {
		return nil, fs.ErrNotExist
	}

	// Return a copy
	result := make([]byte, len(entry.value))
	copy(result, entry.value)
	return result, nil
}

// set stores a value in the database and saves to disk.
func (d *yamlDb) set(bucket, key, val []byte) error {
	d.Lock()

	b := d.data[string(bucket)]
	if b == nil {
		b = make(map[string]*dbEntry)
		d.data[string(bucket)] = b
	}

	if val == nil {
		delete(b, string(key))
	} else {
		entry := b[string(key)]
		if entry == nil {
			entry = &dbEntry{}
			b[string(key)] = entry
		}
		entry.value = val
	}

	d.Unlock()

	return d.save()
}

// setWithStamp stores a value with a timestamp and saves to disk.
func (d *yamlDb) setWithStamp(bucket, key, val []byte, stamp DbStamp) error {
	d.Lock()

	b := d.data[string(bucket)]
	if b == nil {
		b = make(map[string]*dbEntry)
		d.data[string(bucket)] = b
	}

	if val == nil {
		delete(b, string(key))
	} else {
		entry := b[string(key)]
		if entry == nil {
			entry = &dbEntry{}
			b[string(key)] = entry
		}
		entry.value = val
		entry.stamp = stamp
	}

	d.Unlock()

	return d.save()
}

// del removes keys from a bucket and saves to disk.
func (d *yamlDb) del(bucket []byte, keys ...[]byte) error {
	d.Lock()

	b := d.data[string(bucket)]
	if b != nil {
		for _, key := range keys {
			delete(b, string(key))
		}
	}
	d.Unlock()

	return d.save()
}

// getVersion retrieves a value with its timestamp.
func (d *yamlDb) getVersion(bucket, key []byte) (val []byte, stamp DbStamp, err error) {
	d.RLock()
	defer d.RUnlock()

	b := d.data[string(bucket)]
	if b == nil {
		err = fs.ErrNotExist
		return
	}

	entry := b[string(key)]
	if entry == nil || entry.value == nil {
		err = fs.ErrNotExist
		return
	}

	val = make([]byte, len(entry.value))
	copy(val, entry.value)
	stamp = entry.stamp
	return
}

// keys returns an iterator over keys in a bucket with optional prefix filtering.
func (d *yamlDb) keys(bucket, prefix []byte) func(yield func(k, v []byte) bool) {
	return func(yield func(k, v []byte) bool) {
		d.RLock()
		defer d.RUnlock()

		b := d.data[string(bucket)]
		if b == nil {
			return
		}

		// Get sorted keys for consistent iteration
		keys := make([]string, 0, len(b))
		prefixStr := string(prefix)
		for key := range b {
			if prefix == nil || len(key) >= len(prefixStr) && key[:len(prefixStr)] == prefixStr {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)

		for _, key := range keys {
			entry := b[key]
			if entry == nil || entry.value == nil {
				continue
			}

			k := key
			if prefix != nil {
				k = key[len(prefix):]
			}

			if !yield([]byte(k), entry.value) {
				break
			}
		}
	}
}

// close is a no-op for yamlDb since we save on every write.
func (d *yamlDb) close() {
	// Nothing to do - data is already persisted
}

// getVersionKey gets the stamp from the "version" bucket using composite key.
func (d *yamlDb) getVersionKey(bucket, key []byte) (DbStamp, error) {
	// Composite key: bucket + NUL + key
	fk := string(append(append(bucket, 0), key...))

	d.RLock()
	defer d.RUnlock()

	b := d.data["version"]
	if b == nil {
		return DbZero(), fs.ErrNotExist
	}

	entry := b[fk]
	if entry == nil || entry.value == nil {
		return DbZero(), fs.ErrNotExist
	}

	// Value is the binary stamp
	var stamp DbStamp
	if err := stamp.UnmarshalBinary(entry.value); err != nil {
		return DbZero(), err
	}
	return stamp, nil
}

// setVersionKey sets the stamp in the "version" bucket using composite key.
func (d *yamlDb) setVersionKey(bucket, key []byte, stamp DbStamp) error {
	// Composite key: bucket + NUL + key
	fk := string(append(append(bucket, 0), key...))
	stampBytes, _ := stamp.MarshalBinary()

	d.Lock()

	b := d.data["version"]
	if b == nil {
		b = make(map[string]*dbEntry)
		d.data["version"] = b
	}

	b[fk] = &dbEntry{value: stampBytes, stamp: stamp}
	d.Unlock()

	return d.save()
}

// setNoSave sets value without saving (for batch operations like migration).
func (d *yamlDb) setNoSave(bucket, key, val []byte, stamp DbStamp) {
	b := d.data[string(bucket)]
	if b == nil {
		b = make(map[string]*dbEntry)
		d.data[string(bucket)] = b
	}
	b[string(key)] = &dbEntry{value: val, stamp: stamp}
}

// updateVlog updates the version log (vlog bucket).
func (d *yamlDb) updateVlog(bucket, key []byte, stamp DbStamp) {
	d.Lock()
	defer d.Unlock()

	fk := append(append(bucket, 0), key...)
	stampBytes, _ := stamp.MarshalBinary()

	vlog := d.data["vlog"]
	if vlog == nil {
		vlog = make(map[string]*dbEntry)
		d.data["vlog"] = vlog
	}

	// Remove old entries pointing to this key
	for vkey, entry := range vlog {
		if entry != nil && bytes.Equal(entry.value, fk) {
			delete(vlog, vkey)
		}
	}

	// Add new entry: key is stampBytes+fk, value is fk
	vlogKey := string(append(stampBytes, fk...))
	vlog[vlogKey] = &dbEntry{value: fk}
}

// parseStamp parses a timestamp string in format "seconds.nanoseconds".
func parseStamp(s string) DbStamp {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return DbZero()
	}

	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return DbZero()
	}

	nsec, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return DbZero()
	}

	return DbStamp(time.Unix(sec, nsec))
}

// formatStamp formats a timestamp as "seconds.nanoseconds".
func formatStamp(t DbStamp) string {
	return fmt.Sprintf("%d.%09d", t.Unix(), t.UnixNano()%1e9)
}

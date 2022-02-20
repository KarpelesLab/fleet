package fleet

import (
	"errors"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/KarpelesLab/goupd"
)

func (a *Agent) initPath() {
	if goupd.PROJECT_NAME != "unconfigured" {
		// chdir to cache
		c, err := os.UserCacheDir()
		if err != nil {
			panic(err)
		}
		c = filepath.Join(c, goupd.PROJECT_NAME)
		if err := EnsureDir(c); err != nil {
			log.Printf("[fleet] Failed to access cache directory: %s", err)
			return
		}
		log.Printf("[fleet] set cache dir: %s", c)
		a.cache = c
		os.Chdir(c)
	}
}

func (a *Agent) CacheDir() string {
	return a.cache
}

func EnsureDir(c string) error {
	inf, err := os.Stat(c)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(c, 0755)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err == nil && !inf.IsDir() {
		return errors.New("error: file exists at directory location")
	}
	return nil
}

func findFile(filename string) (string, error) {
	// locate file
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), filename)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		p := filepath.Join(cwd, filename)
		if _, err = os.Stat(p); err == nil {
			return p, nil
		}
	}
	p := filepath.Join("/etc/fleet", filename)
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}

	return "", fs.ErrNotExist
}

func (a *Agent) getFile(filename string, cb func([]byte) error) error {
	if a.GetFile != nil {
		v, err := a.GetFile(a, filename)
		if err != nil {
			return err
		}
		return cb(v)
	}

	fn, err := findFile(filename)
	if err != nil {
		log.Printf("[fleet] Failed to locate %s: %s", filename, err)
		return err
	}
	log.Printf("[fleet] located file %s", fn)
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Printf("[fleet] Failed to read %s: %s", filename, err)
		return err
	}
	err = cb(data)
	if err != nil {
		log.Printf("[fleet] Failed to perform %s: %s", filename, err)
		return err
	}
	// only remove after success of callback
	os.Remove(fn)
	return nil
}

package fleet

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
			slog.Error(fmt.Sprintf("[fleet] Failed to access cache directory: %s", err), "event", "fleet:path:init_fail")
			return
		}
		slog.Debug(fmt.Sprintf("[fleet] set cache dir: %s", c), "event", "fleet:path:cachedir")
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
		slog.Error(fmt.Sprintf("[fleet] Failed to locate %s: %s", filename, err), "event", "fleet:path:getfile:notfound")
		return err
	}
	slog.Debug(fmt.Sprintf("[fleet] located file %s", fn), "event", "fleet:path:getfile:located")
	data, err := os.ReadFile(fn)
	if err != nil {
		slog.Warn(fmt.Sprintf("[fleet] Failed to read %s: %s", filename, err), "event", "fleet:path:getfile:read_fail")
		return err
	}
	err = cb(data)
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] Failed to perform %s: %s", filename, err), "event", "fleet:path:getfile:perform_fail")
		return err
	}
	// only remove after success of callback
	os.Remove(fn)
	return nil
}

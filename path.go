package fleet

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/KarpelesLab/goupd"
)

var initialPath string

func initPath() {
	getInitialPath()
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
		os.Chdir(c)
	}
}

func getInitialPath() {
	initialPath, _ = os.Getwd()
	exe, err := os.Executable()
	if err != nil {
		log.Printf("[fleet] failed to get executable path: %s", err)
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		log.Printf("[fleet] failed to parse executable path: %s", err)
		return
	}

	// get directory
	initialPath = filepath.Dir(exe)
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

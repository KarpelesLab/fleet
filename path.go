package fleet

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/TrisTech/goupd"
)

func initPath() {
	if goupd.PROJECT_NAME != "unconfigured" {
		// chdir to cache
		c := GetCacheDir()
		if err := EnsureDir(c); err != nil {
			log.Printf("[fleet] Failed to access cache directory: %s", err)
			return
		}
		log.Printf("[fleet] set cache dir: %s", c)
		os.Chdir(c)
	}
}

func GetCacheDir() string {
	return filepath.Join(cacheFolder, goupd.PROJECT_NAME)
}

func GetConfigDir() string {
	return filepath.Join(globalSettingFolder, goupd.PROJECT_NAME)
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

package fleet

import (
	"log"
	"os"
	"path/filepath"

	"github.com/TrisTech/goupd"
)

func initPath() {
	if goupd.PROJECT_NAME != "unconfigured" {
		// chdir to cache
		c := GetCacheDir()
		inf, err := os.Stat(c)
		if err != nil && os.IsNotExist(err) {
			err = os.MkdirAll(c, 0755)
			if err != nil {
				log.Printf("failed to create cache dir: %s", err)
				return
			}
		} else if err != nil {
			log.Printf("failed to access cache: %s", err)
			return
		} else if err == nil && !inf.IsDir() {
			log.Printf("error: cache is not a directory")
			return
		}
		log.Printf("[fleet] set cache dir: %s", c)
		os.Chdir(c)
	}
}

func GetCacheDir() string {
	return filepath.Join(cacheFolder, goupd.PROJECT_NAME)
}

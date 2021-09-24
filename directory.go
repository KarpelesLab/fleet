package fleet

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

func directoryThread() {
	// this is run in its own gorouting after db is setup
	defer func() {
		// ensure this thread crashing doesn't take the whole process
		if e := recover(); e != nil {
			log.Printf("[fleet] directory thread panic'd, disabling safely. Error: %s", e)
		}
	}()

	// attempt to load jwt
	jwt, err := dbSimpleGet([]byte("fleet"), []byte("internal_key:jwt"))
	if err != nil {
		if _, err := os.Stat(filepath.Join(initialPath, "internal_key.jwt")); err == nil {
			// file exists there, read the files
			jwt, err = ioutil.ReadFile(filepath.Join(initialPath, "internal_key.jwt"))
			if err != nil {
				log.Printf("[fleet] directory jwt failed to load: %s", err)
				return
			}
			// store
			err = dbSimpleSet([]byte("fleet"), []byte("internal_key:jwt"), jwt)
			if err != nil {
				log.Printf("[fleet] directory jwt failed to store: %s", err)
				return
			}
			// remove file
			os.Remove(filepath.Join(initialPath, "internal_key.jwt"))
		} else {
			log.Printf("[fleet] directory jwt not found, disabling directory registration")
			return
		}
	}

	// check jwt signature against kid found in header
	jwtData, err := loadSysJwt(jwt)
	if err != nil {
		log.Printf("[fleet] invalid jwt for directory: %s", err)
		return
	}

	dir, ok := jwtData["directory"].(string)
	if !ok {
		log.Printf("[fleet] directory failed to load: %s", err)
		return
	}

	// jwt contains our jwt token, load the certificate too
	cfg, err := GetClientTlsConfig()
	if err != nil {
		log.Printf("[fleet] failed to get client TLS certificate, directory service disabled: %s", err)
		return
	}

	for {
		// connect to directory, ping, etc
		jwtPingDirectory(dir, jwt, cfg)
		time.Sleep(60 * time.Second)
	}
}

func jwtPingDirectory(dir string, jwt []byte, cfg *tls.Config) {
	// TODO
}

func loadSysJwt(jwt []byte) (map[string]interface{}, error) {
	return nil, errors.New("TODO")
}

package fleet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/KarpelesLab/goupd"
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

	tr := &http.Transport{
		TLSClientConfig: cfg,
		MaxIdleConns:    10,
		IdleConnTimeout: 120 * time.Second,
	}
	client := &http.Client{Transport: tr}

	for {
		// connect to directory, ping, etc
		err = jwtPingDirectory(dir, jwt, client)
		if err != nil {
			log.Printf("[fleet] ping failed: %s", err)
		}
		time.Sleep(60 * time.Second)
	}
}

func jwtPingDirectory(dir string, jwt []byte, client *http.Client) error {
	u := &url.URL{
		Scheme: "https",
		Host:   dir,
		Path:   "/_ping",
	}

	// post body
	post := map[string]interface{}{
		"Name":    Agent.name,
		"Version": goupd.DATE_TAG + "/" + goupd.GIT_TAG,
		"Time":    time.Now().UnixMicro(), // in ms
		"Private": map[string]interface{}{
			"Id":       Agent.id,
			"Division": Agent.division,
		},
	}
	postJson, err := json.Marshal(post)
	if err != nil {
		return err
	}

	//log.Printf("[ping] %s", u)
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(postJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("invalid response from server: %s", resp.Status)
	}

	// make sure to read full response (but drop it for now)
	io.Copy(ioutil.Discard, resp.Body)

	return nil
}

func loadSysJwt(jwt []byte) (map[string]interface{}, error) {
	return nil, errors.New("TODO")
}

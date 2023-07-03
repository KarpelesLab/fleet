package fleet

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func (a *Agent) performSelfIdentificationAttempt() error {
	// let's try various methods to self-id, such as fetching google
	if err := a.performGoogleSelfId(); err == nil {
		return nil
	} else {
		log.Printf("[directory] self auth via google failed: %s", err)
	}
	return errors.New("self-identification was not successful")
}

func (a *Agent) performGoogleSelfId() error {
	// attempt to google self-auth
	// call url: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%23abcdefg&format=full
	// with header: Metadata-Flavor: Google
	key, err := a.getLocalKey()
	if err != nil {
		return err
	}
	pubBin, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	pubHash := sha256.Sum256(pubBin)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%23" + hex.EncodeToString(pubHash[:]) + "&format=full"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP query failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// data is a jwt token on a single line, no linebreak
	_, err = a.GetFile(a, "selfid/google/"+string(data))

	// if file fetch succeeded, it means this instance has been connected to the appropriate host
	// if not, it means failure
	return err
}

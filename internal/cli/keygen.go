package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func (a *App) keygen() *cobra.Command {
	var output, keyID string
	c := &cobra.Command{Use: "keygen --output DIRECTORY --key-id NAME", Short: "Generate an Ed25519 infrastructure publisher key", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if output == "" || keyID == "" {
			return fmt.Errorf("--output and --key-id required")
		}
		pub, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		if e = os.MkdirAll(output, 0700); e != nil {
			return e
		}
		p := filepath.Join(output, "publisher.key")
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.WriteString(base64.StdEncoding.EncodeToString(private) + "\n")
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
		return a.print(map[string]any{"KeyID": keyID, "PublicKey": base64.StdEncoding.EncodeToString(pub), "PrivateKeyFile": p})
	}}
	c.Flags().StringVar(&output, "output", "", "private key directory")
	c.Flags().StringVar(&keyID, "key-id", "", "publisher identity in TrustedKeys")
	return c
}

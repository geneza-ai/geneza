// Command geneza-trust is the OFFLINE trust-set signer. The fleet trust root —
// the key that signs the ClusterConfig envelope — is deliberately separate from
// the per-controller grant keys, so a running controller (which holds only its grant
// key) cannot rewrite the fleet trust set. An operator keeps the trust private
// key off every controller and uses this tool to sign a candidate cluster config
// out of band; the controller then CASes the signed config into the store.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

func main() {
	root := &cobra.Command{
		Use:           "geneza-trust",
		Short:         "Offline trust-set signer for the Geneza fleet ClusterConfig",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newKeygenCmd(), newPubkeyCmd(), newSignCmd(), anchorCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "geneza-trust:", err)
		os.Exit(1)
	}
}

// newKeygenCmd generates a fresh trust keypair. The private key stays OFFLINE
// (never on a controller); the public key + key id are embedded in ClusterConfig
// TrustKeys so agents pin them.
func newKeygenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "keygen", Short: "Generate an offline trust keypair (trust.key/trust.keyid/trust.pub)"}
	outDir := cmd.Flags().String("out-dir", ".", "directory for trust.key/trust.keyid/trust.pub")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		pub, priv, keyID, err := types.GenerateSigningKey()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			return err
		}
		if err := types.SavePrivateKeyPEM(*outDir+"/trust.key", priv); err != nil {
			return err
		}
		if err := os.WriteFile(*outDir+"/trust.keyid", []byte(keyID+"\n"), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(*outDir+"/trust.pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote trust.key (KEEP OFFLINE), trust.keyid, trust.pub to %s\n", *outDir)
		fmt.Printf("  key_id: %s\n  public_key (base64): %s\n", keyID, base64.StdEncoding.EncodeToString(pub))
		return nil
	}
	return cmd
}

// newPubkeyCmd prints the TrustKey JSON entry to embed in a cluster config.
func newPubkeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pubkey", Short: "Print the TrustKey JSON entry for a generated key"}
	dir := cmd.Flags().String("dir", ".", "directory holding trust.keyid + trust.pub")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		keyID, err := os.ReadFile(*dir + "/trust.keyid")
		if err != nil {
			return err
		}
		pubB64, err := os.ReadFile(*dir + "/trust.pub")
		if err != nil {
			return err
		}
		pub, err := base64.StdEncoding.DecodeString(trim(string(pubB64)))
		if err != nil {
			return fmt.Errorf("decode trust.pub: %w", err)
		}
		tk := types.TrustKey{KeyID: trim(string(keyID)), PublicKey: pub}
		b, _ := json.MarshalIndent(tk, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	return cmd
}

// newSignCmd signs a candidate ClusterConfig JSON with the offline trust key,
// producing the Signed envelope the controller CASes into the store. The candidate
// must already list this key in its trust_keys (or agents would reject it).
func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sign", Short: "Sign a candidate ClusterConfig JSON with the offline trust key"}
	keyPath := cmd.Flags().String("key", "trust.key", "offline trust private key (PEM)")
	keyIDPath := cmd.Flags().String("keyid", "trust.keyid", "file holding the trust key id")
	in := cmd.Flags().String("in", "", "candidate ClusterConfig JSON")
	out := cmd.Flags().String("out", "", "output path for the signed envelope")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if *in == "" || *out == "" {
			return fmt.Errorf("--in and --out are required")
		}
		priv, err := types.LoadPrivateKeyPEM(*keyPath)
		if err != nil {
			return err
		}
		keyIDBytes, err := os.ReadFile(*keyIDPath)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		var cc types.ClusterConfig
		if err := json.Unmarshal(raw, &cc); err != nil {
			return fmt.Errorf("parse candidate config: %w", err)
		}
		keyID := trim(string(keyIDBytes))
		// Refuse to sign a config the fleet would reject: an agent verifies a config
		// against its TrustKeys (or GrantKeys when absent), so the signing key must be
		// among them, or the result is dead on arrival.
		if len(cc.TrustKeys) > 0 {
			listed := false
			for _, k := range cc.TrustKeys {
				if k.KeyID == keyID {
					listed = true
					break
				}
			}
			if !listed {
				return fmt.Errorf("candidate trust_keys does not list the signing key %q; agents would reject this config", keyID)
			}
		}
		signed, err := types.Sign(priv, keyID, defaults.ContextClusterConfig, cc)
		if err != nil {
			return err
		}
		env, err := signed.Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, env, 0o644); err != nil {
			return err
		}
		fmt.Printf("signed cluster config v%d -> %s\n", cc.ConfigVersion, *out)
		return nil
	}
	return cmd
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

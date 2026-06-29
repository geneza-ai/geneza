package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newAuditCmd groups workspace forensics: the hash-chained audit log, recorded
// session casts, and the audit-key custody tool that decrypts them. One incident
// workflow — read the log, pull the cast, decrypt it — under one namespace.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Forensics: audit log, session recordings, and audit keys",
	}
	cmd.AddCommand(newAuditLogCmd(), newAuditRecCmd(), newAuditKeyCmd())
	return cmd
}

// newAuditLogCmd builds `geneza audit log` — query the hash-chained audit log.
func newAuditLogCmd() *cobra.Command {
	var (
		since      time.Duration
		limit      int
		typeFilter string
	)
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Query the hash-chained audit log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, _, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			resp, err := api.QueryAudit(ctx, &genezav1.QueryAuditRequest{
				SinceUnix:  time.Now().Add(-since).Unix(),
				TypeFilter: typeFilter,
				Limit:      int32(limit),
			})
			if err != nil {
				return client.Humanize(err)
			}
			for _, r := range resp.GetRecords() {
				fmt.Println(strings.TrimRight(string(r.GetJson()), "\n"))
			}
			if !resp.GetChainOk() {
				// Tamper evidence is the whole point of the chain: scream.
				fmt.Fprintln(os.Stderr, "audit: HASH CHAIN BROKEN — records may have been tampered with")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "audit: %d records, hash chain OK\n", len(resp.GetRecords()))
			return nil
		},
	}
	cmd.Flags().DurationVar(&since, "since", time.Hour, "how far back to query")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum records")
	cmd.Flags().StringVar(&typeFilter, "type", "", "filter by record type")
	return cmd
}

// newAuditRecCmd builds `geneza audit rec` — list and pull recorded session casts.
func newAuditRecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rec",
		Short: "List and pull recorded session casts (requires the audit/replay capability)",
	}
	cmd.AddCommand(newAuditRecLsCmd(), newAuditRecPullCmd())
	return cmd
}

func newAuditRecLsCmd() *cobra.Command {
	var (
		asJSON    bool
		principal string
		workspace string
		limit     int
		offset    int
	)
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List recorded sessions in the workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, _, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			// The workspace is bound by the login certificate; the controller scopes the
			// list to ident.Workspace. The flag only guards against an auditor
			// believing they are listing a workspace their cert does not cover.
			if workspace != "" && workspace != e.Profile.Workspace {
				return fmt.Errorf("your login is scoped to workspace %q, not %q (re-login to switch)",
					e.Profile.Workspace, workspace)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := api.ListRecordings(ctx, &genezav1.ListRecordingsRequest{
				Principal: principal, Limit: int32(limit), Offset: int32(offset),
			})
			if err != nil {
				return client.Humanize(err)
			}
			if asJSON {
				return printJSON(resp)
			}
			rows := make([][]string, 0, len(resp.GetRecordings()))
			for _, r := range resp.GetRecordings() {
				rows = append(rows, []string{
					r.GetSessionId(),
					r.GetNodeId(),
					r.GetPrincipal(),
					r.GetAction(),
					client.Ago(r.GetStartedUnix()),
					byteSize(r.GetSizeBytes()),
					boolStr(r.GetTruncated()),
				})
			}
			client.PrintTable(os.Stdout,
				[]string{"SESSION-ID", "NODE", "PRINCIPAL", "ACTION", "STARTED", "SIZE", "TRUNCATED"}, rows)
			printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	cmd.Flags().StringVar(&principal, "principal", "", "filter to one durable principal (provider:subject)")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows per page (0 = server default)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many rows (paging)")
	cmd.Flags().StringVar(&workspace, "workspace", "", "workspace to list (must match your login; cert-bound)")
	return cmd
}

func newAuditRecPullCmd() *cobra.Command {
	var (
		identityFile string
		outFile      string
	)
	cmd := &cobra.Command{
		Use:   "pull <session-id>",
		Short: "Fetch a recording's ciphertext; decrypt it with -i, or write the raw .cast.age",
		Long: "Pull the encrypted cast for a session. With -i <age-identity-file> the cast is\n" +
			"decrypted locally (the private key never goes to the controller) and written to -o\n" +
			"(or stdout, e.g. | asciinema play -). Without -i the raw .cast.age ciphertext is\n" +
			"written. The manifest sha256 is verified over the fetched ciphertext before any\n" +
			"decrypt.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, _, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()

			stream, err := api.GetRecording(ctx, &genezav1.GetRecordingRequest{SessionId: sessionID})
			if err != nil {
				return client.Humanize(err)
			}
			cipher, manifest, err := readRecordingStream(stream)
			if err != nil {
				return client.Humanize(err)
			}

			// Verify the manifest's sha256 over the fetched ciphertext before trusting
			// (or decrypting) it: the controller already checks at-rest integrity, this is
			// the auditor's independent in-transit check against the node attestation.
			if want := manifest.GetSha256(); len(want) > 0 {
				sum := sha256.Sum256(cipher)
				if !bytes.Equal(sum[:], want) {
					return fmt.Errorf("recording integrity check failed: sha256 mismatch (want %s, got %s)",
						hex.EncodeToString(want), hex.EncodeToString(sum[:]))
				}
			}

			out := cipher
			if identityFile != "" {
				plain, derr := decryptRecording(cipher, identityFile)
				if derr != nil {
					return derr
				}
				out = plain
			}
			return writeRecordingOut(out, outFile)
		},
	}
	cmd.Flags().StringVarP(&identityFile, "identity", "i", "", "age identity file to decrypt the cast (omit to keep ciphertext)")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write to this file (default: stdout)")
	return cmd
}

// readRecordingStream drains the GetRecording stream into the full ciphertext plus
// the manifest carried on the first chunk.
func readRecordingStream(stream genezav1.WorkspaceAPI_GetRecordingClient) ([]byte, *genezav1.RecordingManifest, error) {
	var buf bytes.Buffer
	var manifest *genezav1.RecordingManifest
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if manifest == nil && chunk.GetManifest() != nil {
			manifest = chunk.GetManifest()
		}
		buf.Write(chunk.GetData())
		if chunk.GetEof() {
			break
		}
	}
	if manifest == nil {
		manifest = &genezav1.RecordingManifest{}
	}
	return buf.Bytes(), manifest, nil
}

// decryptRecording opens the age ciphertext under the identities in identityFile.
// The private key is read locally and never leaves the client.
func decryptRecording(cipher []byte, identityFile string) ([]byte, error) {
	f, err := os.Open(identityFile)
	if err != nil {
		return nil, fmt.Errorf("open identity file: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	dr, err := age.Decrypt(bytes.NewReader(cipher), ids...)
	if err != nil {
		return nil, fmt.Errorf("decrypt cast (wrong audit key?): %w", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		return nil, fmt.Errorf("read decrypted cast: %w", err)
	}
	return plain, nil
}

func writeRecordingOut(data []byte, outFile string) error {
	if outFile == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(outFile, data, 0o600)
}

// byteSize renders a byte count compactly for the listing.
func byteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// newAuditKeyCmd is the audit-key custody tool: it generates and inspects the
// age identities that decrypt session recordings. A recording is sealed at the
// agent to an audit recipient (the public half, shipped in the signed cluster
// config); the matching private identity — produced here — is the auditor's to
// safeguard and is the only thing that can ever read a stored cast. The controller
// never holds it, so generation happens on the auditor's node, not the server.
func newAuditKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Generate and inspect the audit identities that decrypt session recordings",
	}
	cmd.AddCommand(newAuditKeyNewCmd(), newAuditKeyRecipientCmd())
	return cmd
}

func newAuditKeyNewCmd() *cobra.Command {
	var outFile string
	cmd := &cobra.Command{
		Use:     "new",
		Aliases: []string{"generate"},
		Short:   "Generate an audit identity; write the private key and print the recipient",
		Long: "Generate a fresh age X25519 audit identity. The PRIVATE key is written to\n" +
			"-o (default audit-identity.key, 0600) or to stdout with -o -; the PUBLIC\n" +
			"recipient (age1...) is printed to stdout for you to drop into the workspace\n" +
			"audit config. Seal recordings to several recipients (the security team's key\n" +
			"plus a break-glass escrow) so losing one identity never orphans a recording.\n\n" +
			"The private key is the auditor's to safeguard: it alone decrypts every\n" +
			"recording sealed to its recipient, and the controller never holds it. Store it\n" +
			"offline (a vault, a hardware key) and back it up — there is no recovery if\n" +
			"it is lost and it was the only recipient.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return fmt.Errorf("generate audit identity: %w", err)
			}
			recipient := id.Recipient().String()
			// The identity string carries the private key; mode 0600 and, for a file,
			// a refusal to clobber keep a custodian from silently overwriting a key
			// that may be the only decryptor of existing recordings.
			if outFile == "-" {
				fmt.Fprintln(cmd.OutOrStdout(), id.String())
			} else {
				if outFile == "" {
					outFile = "audit-identity.key"
				}
				f, err := os.OpenFile(outFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err != nil {
					return fmt.Errorf("write identity file %q (already exists?): %w", outFile, err)
				}
				if _, err := fmt.Fprintln(f, id.String()); err != nil {
					f.Close()
					return fmt.Errorf("write identity file: %w", err)
				}
				if err := f.Close(); err != nil {
					return fmt.Errorf("close identity file: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "audit identity (private key) written to %s — safeguard it; the controller never holds it\n", outFile)
			}
			fmt.Fprintln(cmd.OutOrStdout(), recipient)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write the private identity here (default audit-identity.key; - for stdout)")
	return cmd
}

func newAuditKeyRecipientCmd() *cobra.Command {
	var identityFile string
	cmd := &cobra.Command{
		Use:   "recipient",
		Short: "Print the recipient (public key) for an existing audit identity",
		Long: "Recover the public recipient for an existing audit identity file, e.g. to\n" +
			"re-add it to a workspace config without regenerating (and orphaning) the key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if identityFile == "" {
				return fmt.Errorf("an identity file is required (-i)")
			}
			recipients, err := auditRecipientsFromIdentityFile(identityFile)
			if err != nil {
				return err
			}
			for _, r := range recipients {
				fmt.Fprintln(cmd.OutOrStdout(), r)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFile, "identity", "i", "", "age identity file to read the recipient from")
	return cmd
}

// auditRecipientsFromIdentityFile reads the X25519 identities in a file and
// returns their recipient strings. A file may hold several identities (one
// auditor's set); each maps to one recipient.
func auditRecipientsFromIdentityFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity file: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		x, ok := id.(*age.X25519Identity)
		if !ok {
			return nil, fmt.Errorf("identity file holds a non-X25519 identity; only age X25519 audit keys are supported")
		}
		out = append(out, x.Recipient().String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no identities in %s", path)
	}
	return out, nil
}

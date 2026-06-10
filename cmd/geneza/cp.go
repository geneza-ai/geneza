package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"
	"osie.cloud/geneza/internal/types"
)

func newCpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Copy a single file to/from a node (one side is NODE:PATH; no recursion)",
		Long: `Copy one file between the local machine and a node over SFTP.
Exactly one of SRC, DST must be a remote NODE:PATH spec. Mode bits are
preserved. Directories/recursive copies are not supported in v1 — tar
through 'geneza exec' for trees.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcNode, srcPath, srcRemote := client.SplitRemote(args[0])
			dstNode, dstPath, dstRemote := client.SplitRemote(args[1])
			if srcRemote == dstRemote {
				return errors.New("exactly one of SRC and DST must be NODE:PATH")
			}
			node := srcNode
			if dstRemote {
				node = dstNode
			}

			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()

			sess, err := client.Establish(cmd.Context(), api, e.pool, client.SessionParams{
				Node:   node,
				Action: types.ActionSFTP,
			})
			if err != nil {
				return err
			}
			defer sess.Close()

			sftpc, err := sftp.NewClient(sess.SSH)
			if err != nil {
				return fmt.Errorf("sftp subsystem: %w", err)
			}
			defer sftpc.Close()

			if dstRemote {
				return upload(sftpc, srcPath, dstPath)
			}
			return download(sftpc, srcPath, dstPath)
		},
	}
}

func upload(c *sftp.Client, src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory (recursive copy not supported)", src)
	}
	if dst == "" {
		dst = filepath.Base(src)
	} else if st, serr := c.Stat(dst); serr == nil && st.IsDir() {
		dst = path.Join(dst, filepath.Base(src))
	}
	w, err := c.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("remote create %s: %w", dst, err)
	}
	n, err := io.Copy(w, f)
	cerr := w.Close()
	if err != nil {
		return fmt.Errorf("upload %s: %w", src, err)
	}
	if cerr != nil {
		return fmt.Errorf("upload %s: %w", src, cerr)
	}
	if err := c.Chmod(dst, fi.Mode().Perm()); err != nil {
		return fmt.Errorf("preserve mode on %s: %w", dst, err)
	}
	fmt.Printf("%s -> :%s (%d bytes, mode %04o)\n", src, dst, n, fi.Mode().Perm())
	return nil
}

func download(c *sftp.Client, src, dst string) error {
	r, err := c.Open(src)
	if err != nil {
		return fmt.Errorf("remote open %s: %w", src, err)
	}
	defer r.Close()
	fi, err := r.Stat()
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory (recursive copy not supported)", src)
	}
	if dst == "" || dst == "." {
		dst = path.Base(src)
	} else if st, serr := os.Stat(dst); serr == nil && st.IsDir() {
		dst = filepath.Join(dst, path.Base(src))
	}
	w, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	n, err := io.Copy(w, r)
	cerr := w.Close()
	if err != nil {
		return fmt.Errorf("download %s: %w", src, err)
	}
	if cerr != nil {
		return fmt.Errorf("download %s: %w", src, cerr)
	}
	// O_CREATE mode is masked by umask; enforce the source bits exactly.
	if err := os.Chmod(dst, fi.Mode().Perm()); err != nil {
		return err
	}
	fmt.Printf(":%s -> %s (%d bytes, mode %04o)\n", src, dst, n, fi.Mode().Perm())
	return nil
}

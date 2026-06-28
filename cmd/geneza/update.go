package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/selfupdate"
	"geneza.io/internal/version"
)

func newUpdateCmd() *cobra.Command {
	var (
		checkOnly      bool
		toVersion      string
		timeout        time.Duration
		allowDowngrade bool
	)
	cmd := &cobra.Command{
		Use:     "update",
		Aliases: []string{"upgrade"},
		Short:   "Update the geneza CLI to the latest release",
		Long: "Replaces this geneza binary with the latest published release (or --version TAG),\n" +
			"verifying the download against the release SHA256SUMS. Works on macOS, Linux and\n" +
			"Windows. A Homebrew-managed install is left to `brew upgrade`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			selfupdate.CleanupStaleUpdate() // reclaim a prior Windows .old, if any
			ctx := cmd.Context()

			var rel *selfupdate.Release
			var err error
			if toVersion != "" {
				rel, err = selfupdate.ReleaseByTag(ctx, toVersion)
			} else {
				rel, err = selfupdate.LatestRelease(ctx)
			}
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "current: %s\nlatest:  %s\n", version.Version, rel.TagName)
			if toVersion == "" && selfupdate.IsUpToDate(version.Version, rel.TagName) {
				fmt.Fprintln(os.Stderr, "Already up to date.")
				return nil
			}
			if checkOnly {
				if selfupdate.IsNewer(rel.TagName, version.Version) {
					fmt.Fprintf(os.Stderr, "Update available: %s → %s (run `geneza update`)\n", version.Version, rel.TagName)
				} else {
					fmt.Fprintln(os.Stderr, "No newer release than the running version.")
				}
				return nil
			}

			// Guard against installing an older release over a newer one (a
			// rolled-back/retagged "latest", or an explicit --version downgrade).
			if !selfupdate.IsUpToDate(version.Version, rel.TagName) &&
				!selfupdate.IsNewer(rel.TagName, version.Version) && !allowDowngrade {
				return fmt.Errorf("refusing to downgrade from %s to %s; pass --allow-downgrade to proceed",
					version.Version, rel.TagName)
			}

			fmt.Fprintf(os.Stderr, "Downloading %s…\n", rel.TagName)
			msg, err := selfupdate.Apply(ctx, rel, selfupdate.Options{Timeout: timeout})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s\nRun `geneza version` to confirm.\n", msg)
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "only report whether an update is available")
	cmd.Flags().StringVar(&toVersion, "version", "", "install a specific release tag instead of the latest (e.g. v0.1.0)")
	cmd.Flags().DurationVar(&timeout, "timeout", selfupdate.DefaultTimeout, "download timeout")
	cmd.Flags().BoolVar(&allowDowngrade, "allow-downgrade", false, "allow installing an older release than the running one")
	return cmd
}

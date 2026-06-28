// Command mkproofdb (re)creates the dedicated Postgres database the
// relay-drain-swap-proof controller uses, so each proof run starts from a clean fleet
// state without touching the shared test database. It connects to the admin DSN
// (GENEZA_PROOF_ADMIN_DSN, default the lab "geneza" DB), drops, and recreates
// "geneza_drainproof". It is a proof-harness helper, not part of the product.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

func main() {
	adminDSN := os.Getenv("GENEZA_PROOF_ADMIN_DSN")
	if adminDSN == "" {
		adminDSN = "postgres://geneza:geneza-ha-lab@127.0.0.1:55432/geneza?sslmode=disable"
	}
	dbName := os.Getenv("GENEZA_PROOF_DB")
	if dbName == "" {
		dbName = "geneza_drainproof"
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer c.Close(ctx)
	// Terminate any lingering connections (a previous run's controller) before the drop.
	_, _ = c.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()", dbName)
	if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName); err != nil {
		fmt.Fprintln(os.Stderr, "drop:", err)
		os.Exit(1)
	}
	if _, err := c.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	fmt.Println("recreated", dbName)
}

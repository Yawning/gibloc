// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: LGPL-2.1-only

package gibloc

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"gitlab.com/yawning/gibloc/internal/db"
)

func TestGibloc(t *testing.T) {
	t.Run("Updater", testGiblocUpdater)

	db, err := LoadFile(getDBPath(t))
	require.NoError(t, err, "LoadFile")

	sigOk := db.SignatureValid(nil)
	require.True(t, sigOk, "SignatureValid")

	t.Logf("db: %s", db)

	for _, addr := range []string{
		// RFC 5737/ RFC 3849
		"192.0.2.1", // 192.0.2.0/24 (TEST-NET-1)
		// "198.51.100.69", // 198.51.100.0/24 (TEST-NET-2) Missing :(
		"203.0.113.23", // 203.0.113.0/24 (TEST-NET-3)
		"2001:DB8::1",  // 2001:DB8::/32
		// Google Public DNS
		"8.8.8.8",
		"8.8.4.4",
		"2001:4860:4860::8888",
		"2001:4860:4860::8844",
	} {
		t.Run("QueryIP/"+addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			require.NotNil(t, ip, "net.ParseIP")

			result := db.QueryIP(ip)
			require.NotNil(t, result, "QueryIP")

			t.Logf("%+v", result)
			t.Logf("%s", db.Country(result.CountryCode))
			t.Logf("%s", db.AutonomousSystem(result.ASN))
		})
	}

	for _, ipNetStr := range []string{
		// RFC 5737/ RFC 3849
		"192.0.2.0/24", // (TEST-NET-1)
		// "198.51.100.0/24", (TEST-NET-2) Missing :(
		"203.0.113.0/24", // (TEST-NET-3)
		"2001:DB8::/32",
	} {
		t.Run("QueryIPNet/"+strings.ReplaceAll(ipNetStr, "/", "_"), func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(ipNetStr)
			require.NoError(t, err, "net.ParseCIDR")

			result := db.QueryIPNet(ipNet)
			require.NotNil(t, result, "QueryIPNet")

			t.Logf("%+v", result)
			t.Logf("%s", db.Country(result.CountryCode))
			t.Logf("%s", db.AutonomousSystem(result.ASN))
		})
	}
}

func testGiblocUpdater(t *testing.T) {
	// Note: These tests requires networking, and GetLatestDBVersion is
	// somewhat flaky due to DNS timeouts.
	t.Run("GetLatestDBVersion", func(t *testing.T) {
		if !runNetworkTests() {
			t.Skip("skipping DNS lookup version test")
		}

		ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFn()

		version, err := GetLatestDBVersion(ctx)
		require.NoError(t, err, "GetLatestDBVersion")

		t.Logf("Latest version: %v", version)
	})
	t.Run("GetLatestDB/File", func(t *testing.T) {
		if !runNetworkTests() {
			t.Skip("skipping database download test")
		}

		tmpPath := t.TempDir()
		fn := filepath.Join(tmpPath, "location.db")

		t.Logf("%s", fn)

		ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancelFn()

		db, err := GetLatestDB(ctx, fn, time.Time{})
		require.NoError(t, err, "GetLatestDB")
		require.NotNil(t, db, "GetLatestDB - have a database")

		sigOk := db.SignatureValid(nil)
		require.True(t, sigOk, "SignatureValid")

		_, err = GetLatestDB(ctx, fn, time.Now())
		require.ErrorIs(t, ErrNotModified, err, "GetLatestDB - refetch")

		// Ugh.  This wastes bandwidth, but the test is disabled by default.  Sorry!
		db, err = GetLatestDB(ctx, "", time.Time{})
		require.NoError(t, err, "GetLatestDB")
		require.NotNil(t, db, "GetLatestDB - have a database")
	})
	t.Run("GetLatestDB/Memory", func(t *testing.T) {
		if !runNetworkTests() {
			t.Skip("skipping database download test")
		}

		ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancelFn()

		db, err := GetLatestDB(ctx, "", time.Time{})
		require.NoError(t, err, "GetLatestDB")
		require.NotNil(t, db, "GetLatestDB - have a database")

		sigOk := db.SignatureValid(nil)
		require.True(t, sigOk, "SignatureValid")

		_, err = GetLatestDB(ctx, "", time.Now())
		require.ErrorIs(t, ErrNotModified, err, "GetLatestDB - refetch")

		// Ugh.  This wastes bandwidth, but the test is disabled by default.  Sorry!
		db, err = GetLatestDB(ctx, "", time.Time{})
		require.NoError(t, err, "GetLatestDB")
		require.NotNil(t, db, "GetLatestDB - have a database")
	})
}

func TestDebugDataErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping debug database inconsistency test")
	}

	// This is mostly so I can update the internal fixup table.
	raw, err := os.ReadFile(getDBPath(t))
	require.NoError(t, err, "os.ReadFile")

	if bytes.HasPrefix(raw, xzMagic) {
		rd := bytes.NewReader(raw)
		xzr, err := xz.NewReader(rd)
		require.NoError(t, err, "xz.NewReader")

		raw, err = io.ReadAll(xzr)
		require.NoError(t, err, "io.ReadAll")
	}

	db, err := db.New(raw, true)
	require.NoError(t, err, "db.New")

	vec := db.DebugGetDataErrors()
	for _, s := range vec {
		t.Log(s)
	}
}

func getDBPath(t *testing.T) string {
	f := os.Getenv("LIBLOC_DB_PATH")
	if f == "" {
		// The datafile is 36 MiB.  I'm not going to include it.
		t.Skip("No database available, set `LIBLOC_DB_PATH`")
	}

	return f
}

func runNetworkTests() bool {
	return os.Getenv("GIBLOC_RUN_NETWORK_TESTS") != ""
}

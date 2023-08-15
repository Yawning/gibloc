// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: LGPL-2.1-only

package gibloc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ulikunitz/xz"

	"gitlab.com/yawning/gibloc/internal/db"
)

const (
	maxDownloadSize = 20 * 1024 * 1024  // 10 MiB
	maxDatabaseSize = 150 * 1024 * 1024 // 150 MiB

	userAgent = "location/0.9.17"
)

var (
	// ErrNotModified is the error returned when the remote database is
	// older than the provided timestamp.
	ErrNotModified = errors.New("gibloc: remote database not modified")

	errNoVersionInfo = errors.New("gibloc: no version info received")
	errHTTPStatus    = errors.New("gibloc: unexpected http status")
)

// GetLatestDBVersion queries the ipfire.org DNS server for the latest
// database version.
func GetLatestDBVersion(ctx context.Context) (time.Time, error) {
	var resolver net.Resolver

	records, err := resolver.LookupTXT(ctx, db.VersionCheckDomain())
	if err != nil {
		return time.Time{}, fmt.Errorf("gibloc: failed to query latest version: %w", err)
	}
	for _, record := range records {
		version, err := time.Parse(time.RFC1123, record)
		if err == nil {
			return version, nil
		}
	}

	return time.Time{}, errNoVersionInfo
}

// GetLatestDB fetches the latest database.  If `outPath` is specified, the
// decompressed database will be written to a file.  If `newerThan` is specified,
// then the updater will set the `If-Modified-Since` header.
//
// Note: It is the caller's responsibility to check the database signature.
func GetLatestDB(ctx context.Context, outPath string, newerThan time.Time) (*DB, error) {
	// Build the http request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.DatabaseURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("gibloc: failed to create http request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	if !newerThan.IsZero() {
		req.Header.Set("If-Modified-Since", newerThan.UTC().Format(http.TimeFormat))
	}

	// Get the database.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gibloc: failed to dispatch http request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, ErrNotModified
	default:
		return nil, fmt.Errorf("%w: %d ('%s')", errHTTPStatus, resp.StatusCode, resp.Status)
	}

	rd := &io.LimitedReader{
		R: resp.Body,
		N: maxDownloadSize,
	}

	var wrCtx *getLatestContext
	switch outPath {
	case "":
		rd, err = newXZDecompressReader(rd)
		if err != nil {
			return nil, err
		}
		wrCtx = &getLatestContext{
			wr: new(bytes.Buffer),
		}
	default:
		wrCtx, err = newGetToFileContext(outPath)
	}
	if err != nil {
		return nil, err
	}

	var ok bool
	defer func() {
		if wrCtx.cleanupFn != nil {
			wrCtx.cleanupFn(ok)
		}
	}()

	if _, err = io.Copy(wrCtx.wr, rd); err != nil {
		return nil, fmt.Errorf("gibloc: failed to download database file: %w", err)
	}

	var db *DB
	switch outPath {
	case "":
		db, err = New(wrCtx.wr.(*bytes.Buffer).Bytes())
	default:
		fd := wrCtx.wr.(*os.File) //nolint: forcetypeassert
		_ = fd.Sync()

		db, err = LoadFile(fd.Name())
	}
	if err != nil {
		return nil, err
	}

	if !newerThan.IsZero() {
		// This shouldn't be required, but the timestamp on the server isn't
		// equal to the database file timestamp.
		if !db.CreatedAt().After(newerThan) {
			return nil, ErrNotModified
		}
	}

	ok = true // Inform the updater cleanup that we succeeded.

	return db, nil
}

type getLatestContext struct {
	wr        io.Writer
	cleanupFn func(bool)
}

func newGetToFileContext(outPath string) (*getLatestContext, error) {
	fDir := filepath.Dir(outPath)

	// Download to a temporary location.
	fd, err := os.CreateTemp(fDir, "location.db-*")
	if err != nil {
		return nil, fmt.Errorf("gibloc: failed to create database file: %w", err)
	}
	fName := fd.Name()

	var initOk bool
	defer func() {
		if !initOk {
			_ = fd.Close()
			_ = os.Remove(fName)
		}
	}()

	if err = fd.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("gibloc: failed to chmod database file: %w", err)
	}

	initOk = true
	return &getLatestContext{
		wr: fd,
		cleanupFn: func(ok bool) {
			_ = fd.Close()
			if !ok {
				_ = os.Remove(fName)
			} else {
				// Rename the temporary file to the final one.
				_ = os.Rename(fName, outPath)
			}
		},
	}, nil
}

func newXZDecompressReader(rd io.Reader) (*io.LimitedReader, error) {
	// Initialize the decompression engine.
	xzr, err := (&xz.ReaderConfig{
		SingleStream: true,
	}).NewReader(rd)
	if err != nil {
		return nil, fmt.Errorf("gibloc: failed to initialize xz decompresor: %w", err)
	}
	return &io.LimitedReader{
		R: xzr,
		N: maxDatabaseSize,
	}, nil
}

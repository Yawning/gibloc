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
	// Add some conservative limits.  These are well over double the current
	// actual values as of 2023-08-06.
	maxDownloadSize = 20 * 1024 * 1024  // 10 MiB
	maxDatabaseSize = 200 * 1024 * 1024 // 200 MiB

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

	netLimit := &io.LimitedReader{
		R: resp.Body,
		N: maxDownloadSize,
	}

	// Initialize the decompression engine.
	xzr, err := (&xz.ReaderConfig{
		SingleStream: true,
	}).NewReader(netLimit)
	if err != nil {
		return nil, fmt.Errorf("gibloc: failed to initialize xz decompresor: %w", err)
	}

	buf := new(bytes.Buffer)
	writers := []io.Writer{
		buf,
	}

	// Now that we are committed to downloading the database, open the output
	// file if a path was specified.
	var ok bool
	if outPath != "" {
		fDir := filepath.Dir(outPath)

		// Download to a temporary location.
		f, err := os.CreateTemp(fDir, "location.db-*")
		if err != nil {
			return nil, fmt.Errorf("gibloc: failed to create database file: %w", err)
		}
		fName := f.Name()

		defer func() {
			_ = f.Close()
			if !ok {
				_ = os.Remove(fName)
			} else {
				// And rename the temporary file to the final one.
				_ = os.Rename(fName, outPath)
			}
		}()

		if err = f.Chmod(0o600); err != nil {
			return nil, fmt.Errorf("gibloc: failed to chmod database file: %w", err)
		}

		writers = append(writers, f)
	}

	rd := &io.LimitedReader{
		R: xzr,
		N: maxDatabaseSize,
	}
	wr := io.MultiWriter(writers...)

	if _, err = io.Copy(wr, rd); err != nil {
		return nil, fmt.Errorf("gibloc: failed to download databse file: %w", err)
	}

	// Parse the database.
	db, err := New(buf.Bytes())
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

	ok = true // If we are writing to disk, do the right thing with the file.

	return db, nil
}

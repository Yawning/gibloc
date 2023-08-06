// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

// Package gibloc provides IP location information from a libloc format
// database.
package gibloc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gitlab.com/yawning/gibloc/internal/db"
)

const (
	UnknownAS      = "<unknown Autonomous System>"
	UnknownCountry = "<unknown country>"
)

// Flag expresses flags containing supplementary information about a
// network.
type Flag uint16

const (
	FlagNone              Flag = 0
	FlagAnonymousProxy    Flag = 1 // A1
	FlagSatelliteProvider Flag = 2 // A2
	FlagAnycast           Flag = 4 // A3
	FlagDrop              Flag = 8 // XD
)

var flagToStr = map[Flag]string{
	FlagNone:              "",
	FlagAnonymousProxy:    "anonymous proxy",
	FlagSatelliteProvider: "satellite provider",
	FlagAnycast:           "anycast",
	FlagDrop:              "drop",
}

// String returns a string representation of a flag.
func (f Flag) String() string {
	if f == FlagNone {
		return ""
	}
	vec := make([]string, 0, 4)
	for _, candidate := range []Flag{
		FlagAnonymousProxy,
		FlagSatelliteProvider,
		FlagAnycast,
		FlagDrop,
	} {
		if f&candidate != 0 {
			vec = append(vec, flagToStr[candidate])
		}
	}
	return strings.Join(vec, ",")
}

// Network is the result of a query.
type Network struct {
	CountryCode string
	ASN         uint32
	Flags       Flag
}

// IsAnonymousProxy returns true iff the network is an anonymous proxy (A1).
func (n *Network) IsAnonymousProxy() bool {
	return n.Flags&FlagAnonymousProxy != 0
}

// IsSatelliteProvider returns true iff the network is a satellite provider (A2).
func (n *Network) IsSatelliteProvider() bool {
	return n.Flags&FlagSatelliteProvider != 0
}

// IsAnycast returns true iff the network is a Anycast network (A3).
func (n *Network) IsAnycast() bool {
	return n.Flags&FlagAnycast != 0
}

// IsDrop returns true iff the network is on one of the SPAMHAUS Don't
// Route Or Peer (DROP) lists (XD).  See https://www.spamhaus.org/drop/
// for more details.
func (n *Network) IsDrop() bool {
	return n.Flags&FlagDrop != 0
}

// Equal compares Networks for equality.
func (n *Network) Equal(other *Network) bool {
	return n.CountryCode == other.CountryCode && n.ASN == other.ASN
}

// String returns the string representation of a Network.
func (n *Network) String() string {
	var s string
	switch n.ASN {
	case 0:
		s = n.CountryCode + " (" + UnknownAS + ")"
	default:
		s = fmt.Sprintf("%s (AS%d)", n.CountryCode, n.ASN)
	}
	if flagStr := n.Flags.String(); flagStr != "" {
		s = fmt.Sprintf("%s (%s)", s, flagStr)
	}
	return s
}

type dbMetadata struct {
	CreatedAt   string `json:"created_at"`
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
	License     string `json:"license"`
}

// DB is a libloc database instance.
type DB struct {
	inner    *db.DB
	metadata *dbMetadata
}

// CreatedAt returns the time of database creation (version).
func (d *DB) CreatedAt() time.Time {
	return d.inner.CreatedAt
}

// Vendor returns the database vendor.
func (d *DB) Vendor() string {
	return d.metadata.Vendor
}

// Description returns the database description.
func (d *DB) Description() string {
	return d.metadata.Description
}

// License returns the database license.
func (d *DB) License() string {
	return d.metadata.License
}

// String returns database metadata as a JSON encoded string.
func (d *DB) String() string {
	b, _ := json.Marshal(d.metadata) //nolint:errchkjson
	return string(b)
}

// QueryIP looks up the network information for a given IP address.
func (d *DB) QueryIP(addr net.IP) *Network {
	return d.queryImpl(addr, 0)
}

// QueryIPNet looks up the network information for a given IP network.
func (d *DB) QueryIPNet(ipNet *net.IPNet) *Network {
	clampBits, _ := ipNet.Mask.Size()
	return d.queryImpl(ipNet.IP.Mask(ipNet.Mask), clampBits)
}

func (d *DB) queryImpl(addr net.IP, clampBits int) *Network {
	found := d.inner.Search(addr, clampBits)
	if found != nil {
		return &Network{
			CountryCode: found.CountryCode.String(),
			ASN:         found.ASN,
			Flags:       Flag(found.Flags),
		}
	}

	return nil
}

// Country queries the full country name from a ISO 3166-1 alpha-2 country
// code.  If the country code does not exist, [UnknownCountry] will be
// returned.
func (d *DB) Country(countryCode string) string {
	if len(countryCode) != db.CountryCodeSize {
		return UnknownCountry
	}
	country, ok := d.inner.Countries[db.ISOCodeFromString(countryCode)]
	if !ok {
		return UnknownCountry
	}
	return country.Name
}

// AutonomousSystem quries the Autonomous System (AS) name from an Autonomous
// System Number (ASN).  If the corresponding AS is unknown, [UnknownAS]
// will be returned.
//
// Note: The database's ASN->AS mapping appears to be incomplete.
func (d *DB) AutonomousSystem(asn uint32) string {
	as, ok := d.inner.AutonomousSystems[asn]
	if !ok {
		return UnknownAS
	}
	return as
}

// New creates a DB from a buffer containing the raw database.
func New(raw []byte) (*DB, error) {
	inner, err := db.New(raw, false)
	if err != nil {
		return nil, err
	}

	d := &DB{
		inner: inner,
		metadata: &dbMetadata{
			CreatedAt:   inner.CreatedAt.Format(time.RFC1123),
			Vendor:      inner.Vendor,
			Description: inner.Description,
			License:     inner.License,
		},
	}

	return d, nil
}

// LoadFile creates a DB from a file containing the database.
func LoadFile(f string) (*DB, error) {
	raw, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("gibloc: failed to read db: %w", err)
	}

	return New(raw)
}

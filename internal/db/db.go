// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: LGPL-2.1-only

// Package db implements the libloc on-disk file format.
package db

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"time"
)

const (
	Magic           = "LOCDBXX"
	MagicPrefixSize = 7
	MagicHeaderSize = 8

	VersionOne = 1

	CountryCodeSize = 2
)

var (
	errInvalidMagic       = errors.New("gibloc/internal/db: invalid magic")
	errInvalidHeader      = errors.New("gibloc/internal/db: invalid header")
	errInvalidSection     = errors.New("gibloc/internal/db: invalid section")
	errInvalidString      = errors.New("gibloc/internal/db: invalid string pool index")
	errInvalidObject      = errors.New("gibloc/internal/db: invalid object pool index")
	errCollision          = errors.New("gibloc/internal/db: reference index collision")
	errInvalidNetworkNode = errors.New("gibloc/internal/db: invalid network node")

	byteOrder = binary.BigEndian
)

type ISOCode [CountryCodeSize]byte

func (code ISOCode) String() string {
	return string(code[:])
}

func ISOCodeFromString(s string) ISOCode {
	return ISOCode([]byte(strings.ToUpper(s)))
}

type DB struct {
	CreatedAt   time.Time
	Vendor      string
	Description string
	License     string

	AutonomousSystems ASMap
	Countries         CountryMap

	Digest     []byte
	Signatures [][]byte

	networkTree []NetworkNode
	networks    []Network
	v4Root      *NetworkNode
}

type (
	ASMap      map[uint32]string
	CountryMap map[ISOCode]*Country
)

type Network struct {
	CountryCode ISOCode
	ASN         uint32
	Flags       uint16
}

type NetworkNode struct {
	Zero    *NetworkNode
	One     *NetworkNode
	Network *Network
}

type Country struct {
	ContinentCode ISOCode
	Name          string
}

func (cnt *Country) String() string {
	return cnt.Name
}

type MagicHeader struct {
	Magic   [MagicPrefixSize]byte
	Version uint8
}

func parseMagicHeader(rd *bytes.Reader) (uint8, hash.Hash, error) {
	l := rd.Len()
	if l < MagicHeaderSize {
		return 0, nil, fmt.Errorf("%w: insufficient data", errInvalidMagic)
	}

	var hdr MagicHeader
	if err := binary.Read(rd, byteOrder, &hdr); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", errInvalidMagic, err)
	}
	if l-rd.Len() != MagicHeaderSize {
		panic("BUG: invariant violation, magic header size mismatch")
	}

	if !bytes.Equal(hdr.Magic[:], []byte(Magic)) {
		return 0, nil, errInvalidMagic
	}

	// Sigh.  If you're going to engage in pointless tinfoil hattery
	// and use P-521, then for the love of god, please be consistent
	// in your paranoia and use SHA-512.
	//
	// This is created here, after we know the version so that it is
	// possible to handle upstream deciding to do the reasonable thing
	// later down the line.
	h := sha256.New()

	if err := binary.Write(h, byteOrder, &hdr); err != nil {
		panic("BUG: failed to add to digest: " + err.Error())
	}

	return hdr.Version, h, nil
}

func (db *DB) fixupData() {
	// This used to be a routine that cross-checked that all the networks
	// have a valid country code and AS, but instead it tries to fix known
	// issues instead.
	//
	// The fixups are generated as of the database file from 2023-07-31
	// (git: b2aadb71da8aa7e46e8fecc0a3e928232afc76f4).

	badCCs := map[ISOCode]ISOCode{
		// The database appears to include a whole host of networks
		// with the country code UK instead of GB.  whois for at
		// least some of them appears to be correct, though some of
		// the ranges appear to be in other countries.
		//
		// Apply the best-effort fixup.
		ISOCodeFromString("UK"): ISOCodeFromString("GB"),
	}
	badCCsByAS := map[uint32]ISOCode{
		// Fuck if I know.
		//
		// BAD CC: AC 4143 ASN: 209686 AS: Xingyu Guo
		// BAD CC: DG 4447 ASN: 209686 AS: Xingyu Guo
		// BAD CC: EA 4541 ASN: 209686 AS: Xingyu Guo
		// BAD CC: IC 4943 ASN: 209686 AS: Xingyu Guo
		// BAD CC: TA 5441 ASN: 209686 AS: Xingyu Guo
		209686: ISOCodeFromString("CN"),
	}

	for _, network := range db.networks {
		if fixedCC, doFix := badCCs[network.CountryCode]; doFix {
			network.CountryCode = fixedCC
		}
		if fixedCC, doFix := badCCsByAS[network.ASN]; doFix {
			network.CountryCode = fixedCC
		}
	}
}

func (db *DB) DebugGetDataErrors() []string {
	var ( //nolint:prealloc
		unknownASN uint32
		unknownCC  ISOCode

		ret []string
	)

	missingASes := make(map[uint32]bool)
	for _, network := range db.networks {
		as := db.AutonomousSystems[network.ASN]
		if _, exists := db.Countries[network.CountryCode]; !exists && network.CountryCode != unknownCC {
			ret = append(ret, fmt.Sprintf("Bad CC: %s ASN: %d AS: %+v", network.CountryCode, network.ASN, as))
		}
		if _, exists := db.AutonomousSystems[network.ASN]; !exists && network.ASN != unknownASN {
			missingASes[network.ASN] = true
		}
		if network.Flags > 15 {
			ret = append(ret, fmt.Sprintf("Unknown flags: %x ASN: %d", network.Flags, network.ASN))
		}
	}
	for i := range missingASes {
		ret = append(ret, fmt.Sprintf("Missing AS: %d", i))
	}

	return ret
}

func (db *DB) Search(addr net.IP, clampBits int) *Network {
	_, found := db.searchImpl(addr, clampBits)
	return found
}

func (db *DB) searchImpl(addr net.IP, clampBits int) (*NetworkNode, *Network) {
	var (
		ip   net.IP
		node *NetworkNode
	)
	if ip = addr.To4(); ip != nil && db.v4Root != nil {
		// If we know the address is IPv4, we can reach into the tree
		// to skip traversing the mapping prefix.
		node = db.v4Root
	} else {
		ip = addr.To16()
		if ip == nil {
			ip = addr
		}
		node = &db.networkTree[0]
	}
	found := node.Network

	// Decompose the address into bits, most significant to least
	// significant.
	var n int
searchLoop:
	for _, b := range ip {
		for i := 0; i < 8; i++ {
			bit := b >> (7 - i) & 1

			// Find the next node down the tree.
			var next *NetworkNode
			switch bit {
			case 0:
				next = node.Zero
			case 1:
				next = node.One
			}
			if next == nil {
				// We hit a leaf.  End the search.
				node = nil
				break searchLoop
			}

			// Update the current node.
			node = next
			if node.Network != nil {
				found = node.Network
			}

			n++
			if clampBits > 0 && n >= clampBits {
				break
			}
		}
	}

	return node, found
}

func New(raw []byte, noFix bool) (*DB, error) {
	rd := bytes.NewReader(raw)

	// Parse the common magic header.
	version, h, err := parseMagicHeader(rd)
	if err != nil {
		return nil, err
	}

	// Parse the database.
	var db *DB
	switch version {
	case VersionOne:
		db, err = parseDatabaseV1(raw, rd, h)
	default:
		return nil, fmt.Errorf("%w: invalid version: '%d'", errInvalidMagic, version)
	}
	if err != nil {
		return nil, err
	}

	// Fixup the easy to solve errors in the database.
	if !noFix {
		db.fixupData()
	}
	db.CreatedAt = db.CreatedAt.UTC()

	// Cache the root node of all of the IPv6 mapped IPv4 addresses.
	v4PrefixAddr := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	db.v4Root, _ = db.searchImpl(v4PrefixAddr, 0)

	return db, nil
}

func objErr(descr string, idx uint32) error {
	return fmt.Errorf("%w: %s: %d", errInvalidObject, descr, idx)
}

func VersionCheckDomain() string {
	return fmt.Sprintf("_v%d._db.location.ipfire.org", VersionOne)
}

func DatabaseURL() string {
	return fmt.Sprintf("https://location.ipfire.org/databases/%d/location.db.xz", VersionOne)
}

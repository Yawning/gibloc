// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package db

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

const (
	SignatureMaxLengthV1 = 2048
	HeaderV1Size         = 8 + 4 + 4 + 4 + (4*2)*5 + (2 * 2) + SignatureMaxLengthV1*2 + 32

	NetworkNonLeafV1 = math.MaxUint32
)

type HeaderV1 struct {
	CreatedAt   uint64
	Vendor      uint32
	Description uint32
	License     uint32

	AutonomousSystemOffset uint32
	AutonomousSystemLength uint32

	NetworkDataOffset uint32
	NetworkDataLength uint32

	NetworkTreeOffset uint32
	NetworkTreeLength uint32

	CountriesOffset uint32
	CountriesLength uint32

	PoolOffset uint32
	PoolLength uint32

	Signature1Length uint16
	Signature2Length uint16
	Signature1       [SignatureMaxLengthV1]byte
	Signature2       [SignatureMaxLengthV1]byte

	Padding [32]byte
}

type NetworkNodeV1 struct {
	Zero    uint32
	One     uint32
	Network uint32
}

func (n *NetworkNodeV1) IsLeaf() bool {
	return n.Network != NetworkNonLeafV1
}

func parseHeaderV1(rd *bytes.Reader, h hash.Hash) (*HeaderV1, error) {
	l := rd.Len()
	if l < HeaderV1Size {
		return nil, fmt.Errorf("%w: insufficient data", errInvalidHeader)
	}

	var hdr, toHash HeaderV1
	if err := binary.Read(rd, byteOrder, &hdr); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidHeader, err)
	}
	if l-rd.Len() != HeaderV1Size {
		panic("BUG: invariant violation, V1 header size mismatch")
	}

	// Add the V1 header to the digest, excluding the signatures.
	toHash = hdr
	for i := range toHash.Signature1 {
		toHash.Signature1[i] = 0
	}
	for i := range toHash.Signature2 {
		toHash.Signature2[i] = 0
	}
	toHash.Signature1Length = 0
	toHash.Signature2Length = 0

	if err := binary.Write(h, byteOrder, &toHash); err != nil {
		panic("BUG: failed to add to digest: " + err.Error())
	}

	return &hdr, nil
}

func parseDatabaseV1(raw []byte, rd *bytes.Reader, h hash.Hash) (*DB, error) {
	hdr, err := parseHeaderV1(rd, h)
	if err != nil {
		return nil, err
	}

	if _, err := rd.WriteTo(h); err != nil {
		panic("BUG: failed to add to digest: " + err.Error())
	}

	// Initialize the string pool.  This copies the backing store into a string,
	// but values returned from the pool will not allocate, and `raw` can
	// be GC-ed away.
	stringPool, err := newCStringPoolV1(raw, hdr.PoolOffset, hdr.PoolLength)
	if err != nil {
		return nil, err
	}

	// Parse the various sections.  This also allocates, but queries will
	// not, and `raw` can be GC-ed away.
	asMap, err := parseAutonomousSystemMapV1(raw, hdr, stringPool)
	if err != nil {
		return nil, err
	}
	countryMap, err := parseCountryMapV1(raw, hdr, stringPool)
	if err != nil {
		return nil, err
	}
	networks, err := parseNetworksV1(raw, hdr)
	if err != nil {
		return nil, err
	}

	// The NetworkTree parsing is handled in 2 steps so that we can have
	// nicer to work with nodes in our tree.  The uint32 offset representation
	// is more compact, so we could consider using that as well.
	treeV1, err := parseNetworkTreeV1(raw, hdr)
	if err != nil {
		return nil, err
	}

	tree := make([]NetworkNode, len(treeV1))
	getNetwork := func(idx uint32) *Network {
		if uint64(idx) > uint64(len(networks))-1 {
			return nil
		}
		return &networks[int(idx)]
	}
	getNode := func(idx uint32) *NetworkNode {
		if idx == 0 {
			return nil
		}
		if uint64(idx) > uint64(len(tree))-1 {
			return nil
		}

		return &tree[int(idx)]
	}

	for i, node := range treeV1 {
		if node.IsLeaf() {
			network := getNetwork(node.Network)
			if network == nil {
				return nil, fmt.Errorf("%w: node %d: invalid network: %d", errInvalidNetworkNode, i, node.Network)
			}
			tree[i].Network = network
		}

		zeroIdx, oneIdx := node.Zero, node.One

		zeroNode := getNode(zeroIdx)
		if zeroIdx != 0 && zeroNode == nil {
			return nil, fmt.Errorf("%w: node %d: invalid zero-child: %d", errInvalidNetworkNode, i, zeroIdx)
		}
		oneNode := getNode(oneIdx)
		if oneIdx != 0 && oneNode == nil {
			return nil, fmt.Errorf("%w: node %d: invalid one-child: %d", errInvalidNetworkNode, i, oneIdx)
		}

		tree[i].Zero = zeroNode
		tree[i].One = oneNode
	}

	db := &DB{
		CreatedAt:         time.Unix(int64(hdr.CreatedAt), 0),
		AutonomousSystems: asMap,
		Countries:         countryMap,
		Digest:            h.Sum(nil),
		networkTree:       tree,
		networks:          networks,
	}
	if db.Vendor, err = stringPool.Get(hdr.Vendor); err != nil {
		return nil, fmt.Errorf("%w: Vendor", err)
	}
	if db.Description, err = stringPool.Get(hdr.Description); err != nil {
		return nil, fmt.Errorf("%w: Description", err)
	}
	if db.License, err = stringPool.Get(hdr.License); err != nil {
		return nil, fmt.Errorf("%w: License", err)
	}

	if l := int(hdr.Signature1Length); l > 0 {
		db.Signatures = append(db.Signatures, hdr.Signature1[:l])
	}
	if l := int(hdr.Signature2Length); l > 0 {
		db.Signatures = append(db.Signatures, hdr.Signature2[:l])
	}

	return db, nil
}

func parseAutonomousSystemMapV1(raw []byte, hdr *HeaderV1, stringPool *CStringPoolV1) (ASMap, error) {
	// type AutonomousSystemV1 struct {
	//   Number uint32
	//   Name   uint32
	// }
	const (
		AutonomousSystemV1Size = 4 + 4
		descr                  = "AutonomousSystems"
	)

	section, err := checkSectionV1(raw, descr, hdr.AutonomousSystemOffset, hdr.AutonomousSystemLength)
	if err != nil {
		return nil, err
	}
	sLen := len(section)

	m := make(ASMap)
	for off := 0; off < sLen; off += AutonomousSystemV1Size {
		b := section[off : off+AutonomousSystemV1Size]

		asn := byteOrder.Uint32(b[0:4])
		nameIdx := byteOrder.Uint32(b[4:8])

		name, err := stringPool.Get(nameIdx)
		if err != nil {
			return nil, objErr(descr, nameIdx)
		}

		if _, exists := m[asn]; exists {
			return nil, fmt.Errorf("%w: AutonomousSystem: %d", errCollision, asn)
		}

		m[asn] = name
	}

	return m, nil
}

func parseCountryMapV1(raw []byte, hdr *HeaderV1, stringPool *CStringPoolV1) (CountryMap, error) {
	// type CountryV1 struct {
	//   Code          [2]byte
	//   ContinentCode [2]byte
	//   Name          uint32
	// }
	const (
		CountryV1Size = 2 + 2 + 4
		descr         = "Countries"
	)

	section, err := checkSectionV1(raw, descr, hdr.CountriesOffset, hdr.CountriesLength)
	if err != nil {
		return nil, err
	}
	sLen := len(section)

	m := make(CountryMap)
	for off := 0; off < sLen; off += CountryV1Size {
		b := section[off : off+CountryV1Size]

		countryCode := ISOCodeFromString(string(b[0:2]))
		continentCode := ISOCodeFromString(string(b[2:4]))
		nameIdx := byteOrder.Uint32(b[4:8])

		name, err := stringPool.Get(nameIdx)
		if err != nil {
			return nil, objErr(descr, nameIdx)
		}

		if _, exists := m[countryCode]; exists {
			return nil, fmt.Errorf("%w: Countries: '%s'", errCollision, countryCode)
		}

		m[countryCode] = &Country{
			ContinentCode: continentCode,
			Name:          name,
		}
	}

	return m, nil
}

func parseNetworksV1(raw []byte, hdr *HeaderV1) ([]Network, error) {
	// type NetworkV1 struct {
	//   CountryCode [2]byte
	//   _Padding    [2]byte // C semantics, to naturally align ASN.
	//   ASN         uint32
	//   Flags       uint16
	//   Padding     [2]byte
	// }
	const (
		NetworkV1Size = 2 + 2 + 4 + 2 + 2
		descr         = "Networks"
	)

	section, err := checkSectionV1(raw, descr, hdr.NetworkDataOffset, hdr.NetworkDataLength)
	if err != nil {
		return nil, err
	}
	sLen := len(section)

	vec := make([]Network, 0, sLen/NetworkV1Size)
	for off := 0; off < sLen; off += NetworkV1Size {
		b := section[off : off+NetworkV1Size]

		network := Network{
			CountryCode: ISOCode(b[0:2]),
			ASN:         byteOrder.Uint32(b[4:8]),
			Flags:       byteOrder.Uint16(b[8:10]),
		}

		vec = append(vec, network)
	}

	return vec, nil
}

func parseNetworkTreeV1(raw []byte, hdr *HeaderV1) ([]NetworkNodeV1, error) {
	const (
		NetworkNodeV1Size = 4 + 4 + 4
		descr             = "NetworkTree"
	)

	section, err := checkSectionV1(raw, descr, hdr.NetworkTreeOffset, hdr.NetworkTreeLength)
	if err != nil {
		return nil, err
	}
	sLen := len(section)

	vec := make([]NetworkNodeV1, 0, sLen/NetworkNodeV1Size)
	for off := 0; off < sLen; off += NetworkNodeV1Size {
		b := section[off : off+NetworkNodeV1Size]

		node := NetworkNodeV1{
			Zero:    byteOrder.Uint32(b[0:4]),
			One:     byteOrder.Uint32(b[4:8]),
			Network: byteOrder.Uint32(b[8:12]),
		}

		vec = append(vec, node)
	}

	return vec, nil
}

type CStringPoolV1 struct {
	data string
}

func (p *CStringPoolV1) Get(rawIdx uint32) (string, error) {
	idx := int(rawIdx)
	if uint64(rawIdx) > math.MaxInt || idx >= len(p.data) {
		return "", fmt.Errorf("%w: StringPool[%d]", errInvalidString, rawIdx)
	}

	// The pool is just a series of NUL terminated strings.
	if before, _, found := strings.Cut(p.data[idx:], "\x00"); found {
		return before, nil
	}

	// This is enforced at pool creation.
	panic("BUG: invariant violation, StringPool not NUL terminated")
}

func newCStringPoolV1(raw []byte, offset, length uint32) (*CStringPoolV1, error) {
	data, err := checkSectionV1(raw, "StringPool", offset, length)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: StringPool: 0 length", errInvalidSection)
	}
	if data[len(data)-1] != 0 {
		return nil, fmt.Errorf("%w: StringPool: not NUL terminated", errInvalidSection)
	}

	return &CStringPoolV1{
		data: string(data),
	}, nil
}

func checkSectionV1(raw []byte, descr string, offset, length uint32) ([]byte, error) {
	if uint64(offset) > math.MaxInt || uint64(length) > math.MaxInt {
		return nil, fmt.Errorf("%w: oversized", errInvalidSection)
	}
	oi, li := int(offset), int(length)
	if oi > len(raw) {
		return nil, fmt.Errorf("%w: %s: invalid offset: %d", errInvalidSection, descr, oi)
	}
	data := raw[oi:]
	if li > len(data) {
		return nil, fmt.Errorf("%w: %s: invalid length: %d", errInvalidSection, descr, li)
	}
	data = data[:li]

	return data, nil
}

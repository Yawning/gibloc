// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: LGPL-2.1-only

package gibloc

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

//go:embed internal/assets/signing-key.pem
var liblocSigningKeyPEM string

var liblocSigningKey = func() *ecdsa.PublicKey {
	blk, _ := pem.Decode([]byte(liblocSigningKeyPEM))

	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		panic("gibloc: failed to parse libloc signing key: " + err.Error())
	}

	return pk.(*ecdsa.PublicKey) //nolint:forcetypeassert
}()

// SignatureValid returns true if the database signature is valid.  If
// `publicKey` is nil, the internal hardcoded libloc public key will
// be used.
//
// Note: The gibloc database loader applies fixups to the database
// as part of the load process, however the signature verification
// ignores the fixups.
func (db *DB) SignatureValid(publicKey *ecdsa.PublicKey) bool {
	if publicKey == nil {
		publicKey = liblocSigningKey
	}
	for _, sig := range db.inner.Signatures {
		if ecdsa.VerifyASN1(publicKey, db.inner.Digest, sig) {
			return true
		}
	}
	return false
}

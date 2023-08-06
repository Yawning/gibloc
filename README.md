### gibloc - G(olang l)ibloc ("gib location")
#### Yawning Angel (yawning at schwanenlied dot me)

This is a Go implementation of the libloc[1] database format.  All the other
options left me underwhelmed because I don't want to sign up for an account,
use a shit web service, or pay money.

Features:
- Parse libloc databases.
- Verify libloc database signatures.
- Query for location information by IP or IP network.
- Query country name from ISO 3166-1 alpha-2 country code.
- Query Autonomous System (AS) name from Autonomous System Number (ASN).
- Query current database version via DNS TXT record.
- Fetch the current database from the upstream server.

The database is not included, as it is moderately large and frequently
updated.  It is free to obtain, without an account and this package
can even fetch it for you.

[1]: https://location.ipfire.org/
package sso

import "crypto/elliptic"

// ellipticP256 returns the P-256 curve (used for ES256 tokens).
func ellipticP256() elliptic.Curve { return elliptic.P256() }

// ellipticP384 returns the P-384 curve (used for ES384 tokens).
func ellipticP384() elliptic.Curve { return elliptic.P384() }

// ellipticP521 returns the P-521 curve (used for ES512 tokens).
func ellipticP521() elliptic.Curve { return elliptic.P521() }

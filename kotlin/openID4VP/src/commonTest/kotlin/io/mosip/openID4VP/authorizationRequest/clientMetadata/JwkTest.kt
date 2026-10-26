package io.mosip.openID4VP.authorizationRequest.clientMetadata

import io.mosip.openID4VP.constants.SignatureAlgorithm
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JwkTest {

    private val ed25519Jwk = Jwk(kty = "OKP", crv = "Ed25519", x = "11qYAYdk9J6r9xWhG7f8z1FMvx6bAQJz2-LU8C5QWAc")
    private val p256Jwk = Jwk(kty = "EC", crv = "P-256", x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
    private val p384Jwk = p256Jwk.copy(crv = "P-384")

    @Test
    fun `supports should match EdDSA only to Ed25519 keys`() {
        assertTrue(ed25519Jwk.supports(SignatureAlgorithm.EdDSA))
        assertFalse(p256Jwk.supports(SignatureAlgorithm.EdDSA))
    }

    @Test
    fun `supports should match ES256 only to P-256 keys`() {
        assertTrue(p256Jwk.supports(SignatureAlgorithm.ES256))
        assertFalse(p384Jwk.supports(SignatureAlgorithm.ES256))
        assertFalse(ed25519Jwk.supports(SignatureAlgorithm.ES256))
    }
}

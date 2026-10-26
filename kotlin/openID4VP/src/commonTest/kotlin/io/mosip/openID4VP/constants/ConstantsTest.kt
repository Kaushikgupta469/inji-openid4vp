package io.mosip.openID4VP.constants

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ConstantsTest {

    @Test
    fun `FormatType exposes the wire values defined by the specification`() {
        assertEquals("ldp_vc", FormatType.LDP_VC.value)
        assertEquals("mso_mdoc", FormatType.MSO_MDOC.value)
        assertEquals("dc+sd-jwt", FormatType.DC_SD_JWT.value)
        assertEquals("vc+sd-jwt", FormatType.VC_SD_JWT.value)
    }

    @Test
    fun `FormatType resolves every declared wire value and rejects unknown ones`() {
        FormatType.entries.forEach { assertEquals(it, FormatType.fromValue(it.value)) }

        assertNull(FormatType.fromValue("unknown"))
    }

    @Test
    fun `VPFormatType exposes the wire values defined by the specification`() {
        assertEquals("ldp_vp", VPFormatType.LDP_VP.value)
        assertEquals("ldp_vc", VPFormatType.LDP_VC.value)
        assertEquals("mso_mdoc", VPFormatType.MSO_MDOC.value)
        assertEquals("dc+sd-jwt", VPFormatType.DC_SD_JWT.value)
        assertEquals("vc+sd-jwt", VPFormatType.VC_SD_JWT.value)
    }

    @Test
    fun `VPFormatType resolves every declared wire value and rejects unknown ones`() {
        VPFormatType.entries.forEach { assertEquals(it, VPFormatType.fromValue(it.value)) }

        assertNull(VPFormatType.fromValue("unknown"))
    }

    @Test
    fun `ClientIdScheme resolves every declared wire value and rejects unknown ones`() {
        ClientIdScheme.entries.forEach { assertEquals(it, ClientIdScheme.fromValue(it.value)) }

        assertEquals("pre-registered", ClientIdScheme.PRE_REGISTERED.value)
        assertEquals("redirect_uri", ClientIdScheme.REDIRECT_URI.value)
        assertEquals("did", ClientIdScheme.DID.value)
        assertNull(ClientIdScheme.fromValue("unknown"))
    }

    @Test
    fun `ClientIdPrefix resolves every declared wire value and rejects unknown ones`() {
        ClientIdPrefix.entries.forEach { assertEquals(it, ClientIdPrefix.fromValue(it.value)) }

        assertEquals("pre-registered", ClientIdPrefix.PRE_REGISTERED.value)
        assertEquals("redirect_uri", ClientIdPrefix.REDIRECT_URI.value)
        assertEquals("decentralized_identifier", ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value)
        assertEquals("x509_hash", ClientIdPrefix.X509_HASH.value)
        assertNull(ClientIdPrefix.fromValue("unknown"))
    }

    @Test
    fun `ClientIdPrefix maps to the Draft 23 Client Identifier Scheme and to none for x509_hash`() {
        assertEquals("pre-registered", ClientIdPrefix.toClientIdScheme(ClientIdPrefix.PRE_REGISTERED))
        assertEquals("redirect_uri", ClientIdPrefix.toClientIdScheme(ClientIdPrefix.REDIRECT_URI))
        assertEquals("did", ClientIdPrefix.toClientIdScheme(ClientIdPrefix.DECENTRALIZED_IDENTIFIER))
        assertNull(ClientIdPrefix.toClientIdScheme(ClientIdPrefix.X509_HASH))
    }

    @Test
    fun `SigningAlgorithm resolves every declared wire value and rejects unknown ones`() {
        SigningAlgorithm.entries.forEach { assertEquals(it, SigningAlgorithm.fromValue(it.value)) }

        assertEquals("EdDSA", SigningAlgorithm.EdDSA.value)
        assertEquals("ES256", SigningAlgorithm.ES256.value)
        assertEquals("RS256", SigningAlgorithm.RS256.value)
        assertEquals("PS256", SigningAlgorithm.PS256.value)
        assertNull(SigningAlgorithm.fromValue("unknown"))
    }

    @Test
    fun `SignatureAlgorithm resolves every declared wire value and rejects unknown ones`() {
        SignatureAlgorithm.entries.forEach { assertEquals(it, SignatureAlgorithm.fromValue(it.value)) }

        assertEquals("EdDSA", SignatureAlgorithm.EdDSA.value)
        assertEquals("ES256", SignatureAlgorithm.ES256.value)
        assertNull(SignatureAlgorithm.fromValue("unknown"))
    }

    @Test
    fun `ProofType resolves every declared wire value and rejects unknown ones`() {
        ProofType.entries.forEach { assertEquals(it, ProofType.fromValue(it.value)) }

        assertEquals("Ed25519Signature2020", ProofType.Ed25519Signature2020.value)
        assertEquals("JsonWebSignature2020", ProofType.JsonWebSignature2020.value)
        assertNull(ProofType.fromValue("unknown"))
    }

    @Test
    fun `ResponseType resolves every declared wire value and rejects unknown ones`() {
        ResponseType.entries.forEach { assertEquals(it, ResponseType.fromValue(it.value)) }

        assertEquals("vp_token", ResponseType.VP_TOKEN.value)
        assertNull(ResponseType.fromValue("unknown"))
    }

    @Test
    fun `EncryptionAlgorithm resolves every declared wire value and rejects unknown ones`() {
        EncryptionAlgorithm.entries.forEach {
            assertEquals(it, EncryptionAlgorithm.fromValue(it.value))
        }

        assertEquals("ECDH-ES", EncryptionAlgorithm.ECDH_ES.value)
        assertNull(EncryptionAlgorithm.fromValue("unknown"))
    }

    @Test
    fun `EncryptionMethod resolves every declared wire value and rejects unknown ones`() {
        EncryptionMethod.entries.forEach { assertEquals(it, EncryptionMethod.fromValue(it.value)) }

        assertEquals("A256GCM", EncryptionMethod.A256GCM.value)
        assertNull(EncryptionMethod.fromValue("unknown"))
    }

    @Test
    fun `ResponseMode exposes the wire values defined by the specification`() {
        assertEquals("direct_post", ResponseMode.DIRECT_POST.value)
        assertEquals("direct_post.jwt", ResponseMode.DIRECT_POST_JWT.value)
        assertEquals("iar-post", ResponseMode.IAR_POST.value)
        assertEquals("iar-post.jwt", ResponseMode.IAR_POST_JWT.value)
    }

    @Test
    fun `ContentType exposes the wire values defined by the specification`() {
        assertEquals("application/oauth-authz-req+jwt", ContentType.APPLICATION_JWT.value)
        assertEquals(
            "application/x-www-form-urlencoded",
            ContentType.APPLICATION_FORM_URL_ENCODED.value
        )
    }

    @Test
    fun `SignatureSuiteAlgorithm exposes the wire values defined by the specification`() {
        assertEquals("Ed25519Signature2020", SignatureSuiteAlgorithm.Ed25519Signature2020.value)
        assertEquals("JsonWebSignature2020", SignatureSuiteAlgorithm.JsonWebSignature2020.value)
        assertEquals("Ed25519Signature2018", SignatureSuiteAlgorithm.Ed25519Signature2018.value)
        assertEquals("RSASignature2018", SignatureSuiteAlgorithm.RSASignature2018.value)
    }
}

package io.mosip.openID4VP.jwt.jws

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.VerifierKeyType
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.X509HashTestData
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.JWSUtil
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtHeader
import io.mosip.openID4VP.testData.JWSUtil.Companion.jwtPayload
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.*

class JWSHandlerTest {

    private val publicKeyResolver = mockk<PublicKeyResolver>()
    private val es256KeyPair = X509HashTestData.generateKeyPair(VerifierKeyType.EC_P256)
    private val es256Jws = X509HashTestData.signRequestObject(
        header = mapOf("typ" to "oauth-authz-req+jwt", "alg" to "ES256"),
        payload = mapOf("client_id" to "x509_hash:test"),
        signingKey = es256KeyPair.private
    )

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { Base64.getUrlDecoder().decode(firstArg<String>()) }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }



    @Test
    fun `verify should throw exception with invalid public key`() {
        val publicKey = mockk<java.security.PublicKey>()
        val jwt = JWSUtil.createJWS(jwtPayload, true, jwtHeader)

        val exception = assertFailsWith<Exception> {
            JWSHandler.verify(
                jwt,
                publicKey,
                SignatureAlgorithm.EdDSA,
            )
        }
        assertTrue(exception.message!!.contains("An unexpected exception occurred during verification"))
    }

    @Test
    fun `verify should accept an ES256 signature made with the matching P-256 key`() {
        JWSHandler.verify(es256Jws, es256KeyPair.public, SignatureAlgorithm.ES256)
    }

    @Test
    fun `verify should reject an ES256 signature made with another P-256 key`() {
        val otherKeyPair = X509HashTestData.generateKeyPair(VerifierKeyType.EC_P256)

        val exception = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            JWSHandler.verify(es256Jws, otherKeyPair.public, SignatureAlgorithm.ES256)
        }
        assertEquals("JWS signature verification failed", exception.message)
    }

    @Test
    fun `verify should reject an EC key that is not on the P-256 curve`() {
        val p384PublicKey = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
            .apply { initialize(ECGenParameterSpec("secp384r1")) }
            .generateKeyPair()
            .public

        val exception = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            JWSHandler.verify(es256Jws, p384PublicKey, SignatureAlgorithm.ES256)
        }
        assertTrue(exception.message.contains("An unexpected exception occurred during verification"))
    }

    @Test
    fun `verify should reject a key that does not fit the algorithm`() {
        val ed25519PublicKey = X509HashTestData.generateKeyPair(VerifierKeyType.ED25519).public

        val ed25519KeyWithES256 = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            JWSHandler.verify(es256Jws, ed25519PublicKey, SignatureAlgorithm.ES256)
        }
        val ecKeyWithEdDSA = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            JWSHandler.verify(es256Jws, es256KeyPair.public, SignatureAlgorithm.EdDSA)
        }

        assertTrue(ed25519KeyWithES256.message.contains("An unexpected exception occurred during verification"))
        assertTrue(ecKeyWithEdDSA.message.contains("An unexpected exception occurred during verification"))
    }
}

fun createMockJws(): String {
    val header = Base64.getUrlEncoder().encodeToString(
        """{"alg":"EdDSA","typ":"JWT"}""".toByteArray()
    )
    val payload = Base64.getUrlEncoder().encodeToString(
        """{"sub":"1234567890","name":"John Doe"}""".toByteArray()
    )
    val signature = Base64.getUrlEncoder().encodeToString("mockSignature".toByteArray())
    return "$header.$payload.$signature"
}

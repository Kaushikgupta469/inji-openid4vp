package io.mosip.openID4VP.jwt

import io.mockk.clearAllMocks
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23Serializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.testData.clientMetadataString
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.*

class JWEHandlerJvmTest {
    private lateinit var clientMetadata: ClientMetadataDraft23
    private lateinit var jweHandler: JWEHandler
    private lateinit var publicKey: Jwk
    private val walletNonce = "k5qdSnwnowi-U_iRi0cZuQ"
    private val verifierNonce = "abc.DEF_123-xyz~"

    @BeforeTest
    fun setUp() {
        clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataDraft23Serializer)
        publicKey = clientMetadata.jwks!!.keys[1]
        jweHandler = JWEHandler(
            clientMetadata.authorizationEncryptedResponseAlg!!,
            clientMetadata.authorizationEncryptedResponseEnc!!,
            publicKey,
            walletNonce,
            verifierNonce
        )

    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should contain all the headers parameters of JWE successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assert(encryptedResponse.isNotEmpty())
        val jweParts = encryptedResponse.split(".")
        assertEquals(5, jweParts.size)

        val decodedJWEHeader = convertJsonToMap(String(decodeFromBase64Url(jweParts[0])))

        assertEquals(walletNonce, String(decodeFromBase64Url(decodedJWEHeader["apu"] as String)))
        assertEquals(verifierNonce, String(decodeFromBase64Url(decodedJWEHeader["apv"] as String)))
        assertEquals(publicKey.kid, decodedJWEHeader["kid"])
        assertEquals("ECDH-ES", decodedJWEHeader["alg"])
        assertEquals("A256GCM", decodedJWEHeader["enc"])
        assertEquals("OKP", (decodedJWEHeader["epk"] as Map<*, *>)["kty"])
        assertEquals("X25519", (decodedJWEHeader["epk"] as Map<*, *>)["crv"])
    }

}

package io.mosip.openID4VP.jwt.jws

import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.HEADER
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.SIGNATURE
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256SignatureVerifierImpl
import java.nio.charset.StandardCharsets
import java.security.PublicKey
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getObjectMapper

private val className = JWSHandler::class.simpleName!!
class JWSHandler {
    enum class JwsPart(val number: Int) {
        HEADER(0),
        PAYLOAD(1),
        SIGNATURE(2)
    }

    companion object {
        // The JWS alg selects the verifier, so a key of another type is rejected
        fun verify(jws: String, publicKey: PublicKey, algorithm: SignatureAlgorithm) {
            val verificationResult: Boolean
            try {
                val parts = jws.split(".")
                val header = parts[HEADER.number]
                val payload = parts[PAYLOAD.number]
                val signature = decodeFromBase64Url(parts[SIGNATURE.number])

                val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)

                val signatureVerifier = when (algorithm) {
                    SignatureAlgorithm.EdDSA -> ED25519SignatureVerifierImpl()
                    SignatureAlgorithm.ES256 -> ES256SignatureVerifierImpl()
                }
                verificationResult = signatureVerifier.verify(
                    publicKey = publicKey,
                    signData = messageBytes,
                    signature = signature,
                    provider = null
                )
            } catch (ex: Exception) {
                throw OpenID4VPExceptions.VerificationFailure(
                    "An unexpected exception occurred during verification: ${ex.message}",
                    className
                )
            }

            if (!verificationResult) {
                throw OpenID4VPExceptions.VerificationFailure(
                    "JWS signature verification failed", className
                )
            }
        }

        fun extractDataJsonFromJws(jws: String, part: JwsPart): MutableMap<String, Any> {
            val components = jws.split(".")
            val payload = components[part.number]
            val decodedString = decodeFromBase64Url(payload)
            return convertJsonToMap(String(decodedString, Charsets.UTF_8))
        }

        fun createUnsignedJWS(header: Map<String, Any>, payload: Map<String, Any>): String {
            val encodedHeader =
                encodeToBase64Url(
                    getObjectMapper().writeValueAsString(header).toByteArray(StandardCharsets.UTF_8)
                )
            val encodedPayload = encodeToBase64Url(
                getObjectMapper().writeValueAsString(payload).toByteArray(StandardCharsets.UTF_8)
            )
            return "$encodedHeader.$encodedPayload"
        }
    }
}
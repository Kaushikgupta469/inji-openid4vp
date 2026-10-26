package io.mosip.openID4VP.testData

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class JWSUtil {
    companion object {
        private const val ed25519PrivateKey = "7JGq310it2uq1_KZ3kARpoUB36KaVO2Ki5VeqQ_856A"
        private const val didDocumentUrl = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
        private const val publicKeyId = "$didDocumentUrl#key-0"
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
            put("kid", publicKeyId)
        }
        val jwtPayload = mutableMapOf(
            "userId" to "b07f85be",
            "iss" to  "https://mock-verifier.com",
            "exp" to "153452683"
        )

        private fun replaceCharactersInB64(encodedB64: String): String {
            return encodedB64.replace('+', '-')
                .replace('/', '_')
                .replace("=+$".toRegex(), "")
        }

        fun encodeB64(str: String): String {
            val encoded = Base64.getEncoder().encodeToString(str.toByteArray())
            return replaceCharactersInB64(encoded)
        }

        private fun createSignatureED(privateKey: ByteArray, message: String): String {
            val signer = Ed25519Signer()
            val keyParams = Ed25519PrivateKeyParameters(privateKey, 0)
            signer.init(true, keyParams)
            val messageBytes = message.toByteArray(StandardCharsets.UTF_8)
            signer.update(messageBytes, 0, messageBytes.size)
            val signature = signer.generateSignature()
            return replaceCharactersInB64(Base64.getEncoder().encodeToString(signature))
        }

        fun buildTestJwk(
            kid: String? = "test-kid",
            alg: String = "EdDSA",
            kty: String = "OKP",
            use: String = "sig",
            crv: String = "Ed25519",
            x: String = "11qYAYdk9J6r9xWhG7f8z1FMvx6bAQJz2-LU8C5QWAc",
            y: String? = null
        ): Jwk {
            return Jwk(
                kty = kty,
                use = use,
                alg = alg,
                crv = crv,
                x = x,
                y = y,
                kid = kid
            )
        }

        fun generateP256PublicKey(): ECPublicKey {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            return keyPairGenerator.generateKeyPair().public as ECPublicKey
        }

        fun ECPublicKey.toP256Jwk(kid: String? = "test-ec-kid", use: String = "sig"): Jwk {
            return buildTestJwk(
                kid = kid,
                alg = "ES256",
                kty = "EC",
                use = use,
                crv = "P-256",
                x = w.affineX.toBase64Url(),
                y = w.affineY.toBase64Url()
            )
        }

        fun BigInteger.toBase64Url(): String {
            val bytes = toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            val padded = ByteArray(32 - bytes.size) + bytes
            return Base64.getUrlEncoder().withoutPadding().encodeToString(padded)
        }

        fun createJWS(
            authorizationRequestParam: Any?,
            addValidSignature: Boolean,
            jwsHeader: JsonObject?
        ): String {
            val mapper = jacksonObjectMapper()
            val header = jwsHeader ?: this.jwtHeader
            val header64 = encodeB64(header.toString())
            val payload64 = encodeB64(mapper.writeValueAsString(authorizationRequestParam))
            val preHash = "$header64.$payload64"
            val privateKey = Base64.getUrlDecoder().decode(ed25519PrivateKey.toByteArray())
            val signature64 = if(addValidSignature)
                createSignatureED(privateKey, preHash)
            else
                "aW52YWxpZC1zaWdu"
            return "$header64.$payload64.$signature64"
        }

    }
}


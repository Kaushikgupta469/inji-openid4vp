package io.mosip.openID4VP.jwt.jwe

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.util.Base64URL
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider

private val className = JWEHandler::class.simpleName!!

class JWEHandler(
    private val keyEncryptionAlg: String,
    private val contentEncryptionAlg: String,
    private val publicKey: Jwk,
    private val walletNonce: String,
    private val verifierNonce: String
) {

    fun generateEncryptedResponse(payload: Map<String, Any>): String {
        if (keyEncryptionAlg != "ECDH-ES" || contentEncryptionAlg != "A256GCM") {
            throw OpenID4VPExceptions.UnsupportedOperationException(
                "Unsupported encryption configuration: keyEncryptionAlgorithm=$keyEncryptionAlg, contentEncryptionAlgorithm=$contentEncryptionAlg. Supported configuration: keyEncryptionAlgorithm=ECDH-ES, contentEncryptionAlgorithm=A256GCM",
                className
            )
        }
        try {
            val header = JWEHeader.Builder(
                JWEAlgorithm.parse(keyEncryptionAlg),
                EncryptionMethod.parse(contentEncryptionAlg)
            )
                .keyID(publicKey.kid)
                .agreementPartyUInfo(Base64URL.encode(walletNonce))
                .agreementPartyVInfo(Base64URL.encode(verifierNonce))
                .build()

            val encrypter = EncryptionProvider.getEncrypter(publicKey)
            val jweObject = JWEObject(header, Payload(payload))
            jweObject.encrypt(encrypter)

            return jweObject.serialize()
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.JweEncryptionFailure(
                "JWE Encryption failed : " + (exception.message ?: "Unknown error"),
                className,
                exception
            )
        }
    }
}
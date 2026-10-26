package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import com.nimbusds.jose.jwk.Curve
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateRequestObjectSigningAlgSupported
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.encodeToBase64UrlWithoutPadding
import io.mosip.openID4VP.common.generateHash
import io.mosip.openID4VP.common.isSelfSigned
import io.mosip.openID4VP.common.parseX509Certificate
import io.mosip.openID4VP.common.validateCertificationPath
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.DecoderException
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

private val className = X509HashPrefixAuthorizationRequestHandler::class.simpleName!!

private const val X5C = "x5c"

private const val DIGITAL_SIGNATURE_KEY_USAGE = 0

// base64url SHA-256 hash without padding
private val CERTIFICATE_HASH_PATTERN = Regex("^[A-Za-z0-9_-]{43}$")

// x509_hash Client Identifier Prefix, OpenID4VP 1.0 section 5.9.3
class X509HashPrefixAuthorizationRequestHandler(
    clientId: String,
    specVersion: SpecVersion,
    authorizationRequestParameters: MutableMap<String, Any>,
    walletConfig: WalletConfig,
    setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit,
    walletNonce: String,
) : ClientIdPrefixBasedAuthorizationRequestHandler(
    clientId,
    specVersion,
    authorizationRequestParameters,
    walletConfig,
    setResponseDispatchInfo,
    walletNonce
) {
    private val certificateHash = clientId.removePrefix("${ClientIdPrefix.X509_HASH.value}:")

    override fun validateClientId() {
        if (!walletConfig.clientIdPrefixesSupported.contains(ClientIdPrefix.X509_HASH)) {
            throw OpenID4VPExceptions.InvalidData(
                "client_id_prefix ${ClientIdPrefix.X509_HASH.value} is not supported by wallet",
                className
            )
        }
        if (!CERTIFICATE_HASH_PATTERN.matches(certificateHash)) {
            throw OpenID4VPExceptions.InvalidData(
                "client_id must be ${ClientIdPrefix.X509_HASH.value}:<base64url-encoded SHA-256 hash of the leaf certificate>",
                className
            )
        }
    }

    override fun isSignedRequestSupported(): Boolean {
        return true
    }

    override fun isUnsignedRequestSupported(): Boolean {
        return false
    }

    override fun clientIdPrefix(): String {
        return ClientIdPrefix.X509_HASH.value
    }

    override fun confirmSpecVersionIdentifiedFromRequest(): Boolean {
        return specVersion == SpecVersion.V1
    }

    override fun extractPublicKey(algorithm: SignatureAlgorithm, jwsHeader: Map<String, Any>): PublicKey {
        val certificateChainBytes = extractCertificateChainBytes(jwsHeader)

        if (encodeToBase64UrlWithoutPadding(generateHash(certificateChainBytes.first())) != certificateHash) {
            throw invalidRequestObject("client_id does not match the SHA-256 hash of the leaf certificate in x5c")
        }

        val certificateChain = certificateChainBytes.mapIndexed { index, certificateBytes ->
            try {
                parseX509Certificate(certificateBytes)
            } catch (e: Exception) {
                throw invalidRequestObject("x5c[$index] is not a valid DER-encoded X.509 certificate", e)
            }
        }
        val leafCertificate = certificateChain.first()

        validateAlgorithmMatchesKey(algorithm, leafCertificate.publicKey)
        validateValidityPeriod(leafCertificate)
        validateKeyUsage(leafCertificate)
        validateTrustChain(certificateChain)

        return leafCertificate.publicKey
    }

    override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> {
        validateRequestObjectSigningAlgSupported(walletConfig)
        return walletConfig.toWalletMetadata(specVersion)
    }

    private fun extractCertificateChainBytes(jwsHeader: Map<String, Any>): List<ByteArray> {
        val certificateChain = jwsHeader[X5C] as? List<*>
        if (certificateChain.isNullOrEmpty()) {
            throw invalidRequestObject("x5c certificate chain is missing in the JWS header")
        }
        return certificateChain.mapIndexed { index, certificate ->
            if (certificate !is String || certificate.isBlank()) {
                throw invalidRequestObject("x5c[$index] must be a base64-encoded DER X.509 certificate")
            }
            // x5c entries are standard base64, not base64url
            try {
                Base64.decode(certificate)
            } catch (e: DecoderException) {
                throw invalidRequestObject("x5c[$index] must be a base64-encoded DER X.509 certificate", e)
            }
        }
    }

    // OpenID4VP 1.0 section 5.9.3: the Wallet MUST validate the trust chain of the leaf certificate
    private fun validateTrustChain(certificateChain: List<X509Certificate>) {
        val trustAnchors = parseTrustAnchors()
        if (trustAnchors.isEmpty()) {
            throw invalidRequestObject("No trust anchors are configured to validate the x5c certificate chain")
        }
        try {
            validateCertificationPath(certificateChain, trustAnchors)
        } catch (e: GeneralSecurityException) {
            throw invalidRequestObject("x5c certificate chain is not trusted: ${e.message}", e)
        }
        // HAIP 1.0: the leaf must not be self-signed. Checked after the chain is trusted, so an untrusted key
        // is never used to verify a signature (CVE-2024-30172)
        if (certificateChain.first().isSelfSigned()) {
            throw invalidRequestObject("Leaf certificate in x5c must not be self-signed")
        }
    }

    private fun parseTrustAnchors(): List<X509Certificate> {
        return walletConfig.verifierTrustAnchors.mapIndexed { index, trustAnchor ->
            try {
                parseX509Certificate(Base64.decode(trustAnchor))
            } catch (e: Exception) {
                throw invalidRequestObject(
                    "verifierTrustAnchors[$index] in the wallet configuration is not a base64-encoded DER X.509 certificate",
                    e
                )
            }
        }
    }

    private fun validateKeyUsage(certificate: X509Certificate) {
        val keyUsage = certificate.keyUsage ?: return
        if (!keyUsage[DIGITAL_SIGNATURE_KEY_USAGE]) {
            throw invalidRequestObject("Key usage of the leaf certificate in x5c does not allow digitalSignature")
        }
    }

    private fun validateAlgorithmMatchesKey(algorithm: SignatureAlgorithm, publicKey: PublicKey) {
        val isMatchingKey = when (algorithm) {
            SignatureAlgorithm.EdDSA -> publicKey.algorithm.equals("Ed25519", ignoreCase = true)
            SignatureAlgorithm.ES256 ->
                publicKey is ECPublicKey && Curve.forECParameterSpec(publicKey.params) == Curve.P_256
        }
        if (!isMatchingKey) {
            throw invalidRequestObject("Signing algorithm ${algorithm.value} does not match the leaf certificate key")
        }
    }

    private fun validateValidityPeriod(certificate: X509Certificate) {
        try {
            certificate.checkValidity()
        } catch (e: CertificateExpiredException) {
            throw invalidRequestObject("Leaf certificate in x5c has expired", e)
        } catch (e: CertificateNotYetValidException) {
            throw invalidRequestObject("Leaf certificate in x5c is not yet valid", e)
        }
    }

    private fun invalidRequestObject(message: String, cause: Throwable? = null) =
        OpenID4VPExceptions.InvalidData(
            message,
            className,
            OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT,
            cause = cause
        )
}

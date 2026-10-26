package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.validateRequestObjectSigningAlgSupported
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.resolveJwksFromUri
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidVerifier
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Security
import java.security.spec.X509EncodedKeySpec

private val className = PreRegisteredSchemeAuthorizationRequestHandler::class.simpleName!!

class PreRegisteredSchemeAuthorizationRequestHandler(
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

    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    init {
        Security.addProvider(provider)
    }

    override fun validateClientId() {
        if (!walletConfig.validateTrustedVerifier) return

        if (walletConfig.trustedVerifiers.none { it.clientId == super.clientId }) {
            throw InvalidVerifier(
                "Verifier is not trusted by the wallet",
                className
            )
        }
    }

    override fun isSignedRequestSupported(): Boolean {
        return true
    }

    override fun isUnsignedRequestSupported(): Boolean {
        if (walletConfig.validateTrustedVerifier) {
            val preRegisteredVerifier = verifier(super.clientId)

            return preRegisteredVerifier.allowUnsignedRequest
        }

        return true
    }

    override fun clientIdPrefix(): String {
        return ClientIdPrefix.PRE_REGISTERED.value
    }

    override fun extractPublicKey(
        algorithm: SignatureAlgorithm,
        jwsHeader: Map<String, Any>,
    ): PublicKey {
        val kid = jwsHeader["kid"] as? String
        val verifier = walletConfig.trustedVerifiers.firstOrNull { it.clientId == super.clientId }
            ?: throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed for keyId = $kid, algorithm: ${algorithm.name}",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        val jwksUri = verifier.jwksUri
            ?: throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )

        val jwkSet = resolveJwksFromUri(jwksUri, className)

        return filterAndExtractKey(jwkSet.keys, kid, algorithm)
    }

    private fun filterAndExtractKey(
        keys: List<Jwk>,
        kid: String?,
        algorithm: SignatureAlgorithm,
    ): PublicKey {
        if (kid != null) {
            val byKid = keys.firstOrNull { it.kid == kid }
                ?: throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                    "Public key extraction failed for kid: $kid",
                    className,
                    OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
                )
            return byKid.toJavaPublicKey()
        }

        val matchingKeys: List<Jwk> =
            keys.filter { it.supports(algorithm) && it.use.equals("sig") }

        val selectedKey = when {
            matchingKeys.isEmpty() -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "No public key found for algorithm: ${algorithm.name} with signature usage",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )

            matchingKeys.size == 1 -> matchingKeys.first()
            else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed - Multiple ambiguous keys found for ${algorithm.name} with signature usage",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }

        try {
            return selectedKey.toJavaPublicKey()
        } catch (e: Exception) {
            throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed- ${e.message}",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }
    }


    private fun Jwk.toJavaPublicKey(): PublicKey {
        return when (kty.uppercase()) {
            "OKP" -> when (crv) {
                "Ed25519" -> buildEd25519PublicKey(x)
                else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                    "Public key extraction failed - Curve - $crv is not supported. Supported: Ed25519",
                    className
                )
            }

            "EC" -> when (crv) {
                "P-256" -> buildP256PublicKey(x, y)
                else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                    "Public key extraction failed - Curve - $crv is not supported. Supported: P-256",
                    className
                )
            }

            else -> throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed - KeyType - $kty is not supported. Supported: OKP, EC",
                className
            )
        }
    }

    private fun buildP256PublicKey(x: String, y: String?): PublicKey {
        if (y == null) {
            throw OpenID4VPExceptions.PublicKeyResolutionFailed(
                "Public key extraction failed - y is required for an EC key",
                className
            )
        }
        val curveSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val point = curveSpec.curve.validatePoint(
            BigInteger(1, decodeFromBase64Url(x)),
            BigInteger(1, decodeFromBase64Url(y))
        )
        return KeyFactory.getInstance("EC", provider).generatePublic(ECPublicKeySpec(point, curveSpec))
    }

    private fun buildEd25519PublicKey(x: String): PublicKey {
        val publicKeyBytes = decodeFromBase64Url(x)
        val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
        val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
        val encodedKey = subjectPublicKeyInfo.encoded

        val keySpec = X509EncodedKeySpec(encodedKey)
        val keyFactory = KeyFactory.getInstance("EdDSA", provider)

        return keyFactory.generatePublic(keySpec)
    }


    override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> {
        validateRequestObjectSigningAlgSupported(walletConfig)
        return walletConfig.toWalletMetadata(specVersion)
    }

    override fun validateClientAuthenticity() {
        if (walletConfig.validateTrustedVerifier) {
            val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
                ?: throw OpenID4VPExceptions.MissingInput(
                    fieldPath = RESPONSE_URI.value,
                    message = "",
                    className = className,
                    notifyVerifier = false
                )

            val preRegisteredVerifier = verifier(super.clientId)

            if (!preRegisteredVerifier.responseUris.contains(responseUri)) {
                throw InvalidVerifier(
                    "Verifier is not trusted by the wallet",
                    className
                )
            }
        }
    }

    private fun verifier(clientId: String): Verifier {
        return walletConfig.trustedVerifiers.find { it.clientId == clientId }
            ?: throw InvalidVerifier("Verifier is not trusted by the wallet", className)
    }
}

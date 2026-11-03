package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey


// RFC 3986 (https://www.rfc-editor.org/rfc/rfc3986#section-3) https URI
private const val URL_PATTERN =
    "^https://(?:[\\w-]+\\.)+[\\w-]+(?::\\d+)?" +
        "(?:/(?:[\\w\\-.~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*" +
        "(?:\\?(?:[\\w\\-.~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?" +
        "(?:#(?:[\\w\\-.~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?$"

private val URL_REGEX = Regex(URL_PATTERN)

fun isValidUrl(url: String): Boolean {
    return URL_REGEX.matches(url)
}

fun convertJsonToMap(jsonString: String): MutableMap<String, Any> {
    return getObjectMapper().readValue(
        jsonString,
        object : TypeReference<MutableMap<String, Any>>() {})
}

fun isJWS(input: String): Boolean {
    return input.split(".").size == 3
}

fun determineHttpMethod(method: String): HttpMethod {
    return when (method.lowercase()) {
        "get" -> HttpMethod.GET
        "post" -> HttpMethod.POST
        else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
    }
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

fun generateNonce(minEntropy: Int = 16): String {
    val secureRandom = SecureRandom()
    val bytes = ByteArray(minEntropy)
    secureRandom.nextBytes(bytes)
    return encodeToBase64Url(bytes)
}

fun validate(
    key: String,
    value: String?,
    className: String,
    fieldType: String = "String",
    notifyVerifier: Boolean = true
) {
    if (value == null || value == "null" || value.isEmpty()) {
        throw if (value == null) {
            OpenID4VPExceptions.MissingInput(listOf(key), "", className, notifyVerifier = notifyVerifier)
        } else {
            OpenID4VPExceptions.InvalidInput(listOf(key), fieldType, className, notifyVerifier = notifyVerifier)
        }
    }
}

inline fun <reified T> encodeToJsonString(data: T, fieldName: String, className: String): String {
    try {
        val objectMapper =
            jacksonObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)
        return objectMapper.writeValueAsString(data)
    } catch (exception: Exception) {
        throw OpenID4VPExceptions.JsonEncodingFailed(
            listOf(fieldName),
            exception.message.toString(),
            className
        )
    }
}

fun ByteArray.toHex(): String {
    return this.joinToString("") { "%02x".format(it) }
}

fun hexToByteArray(hex: String): ByteArray {
    return ByteArray(hex.length / 2) { i ->
        hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
    }
}

fun getObjectMapper(): ObjectMapper {
    return JacksonObjectMapper.instance
}

fun hashData(data: String, algorithm: String = "SHA-256"): String {
    val digest = MessageDigest.getInstance(algorithm)
    val hash = digest.digest(data.toByteArray(Charsets.UTF_8))
    return encodeToBase64Url(hash)
}

fun createNestedPath(
    inputDescriptorId: String,
    nestedPath: String?,
    format: FormatType
): PathNested? {
    if (nestedPath == null) return null
    return PathNested(
        id = inputDescriptorId,
        format = format.value,
        path = nestedPath
    )
}

fun createDescriptorMapPath(vpIndex: Int) = "$[$vpIndex]"

internal fun resolveJwksFromUri(jwksUri: String, className: String): Jwks {
    return try {
        val response: NetworkResponse =
            NetworkManagerClient.sendHTTPRequest(jwksUri, HttpMethod.GET)

        if (!response.isOk()) {
            throw InvalidData(
                "Error while fetching jwks information, status code: ${response.statusCode} with body: ${response.body}",
                className
            )
        }

        getObjectMapper().readValue(response.body, Jwks::class.java)
    } catch (e: Exception) {
        throw InvalidData(
            "Public key extraction failed - Unable to fetch/parse jwks from $jwksUri due to ${e.message}",
            className,
            OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
        )
    }
}

fun resolveSdJwtKeyAndAlg(sdJwtCredential: String, className: String): Pair<String, String> {

    val sdJwt = sdJwtCredential.split("~")[0]
    val payload = JWSHandler.extractDataJsonFromJws(sdJwt, JWSHandler.JwsPart.PAYLOAD)

    val cnf = payload["cnf"] as? Map<*, *>
        ?: throw InvalidData("cnf missing in SD-JWT", className)

    val jwk = cnf["jwk"] as? Map<*, *>
    if (jwk != null) {
        val alg = resolveAlgFromJwk(jwk, className)
        val jwkJson = jacksonObjectMapper().writeValueAsString(jwk)
        return jwkJson to alg
    }

    val kid = cnf["kid"] as? String
        ?: throw InvalidData("cnf must contain either 'jwk' or 'kid'", className)

    return kid to resolveJWSAlgorithm(kid, className)
}

private fun resolveAlgFromJwk(jwk: Map<*, *>, className: String): String {
    val explicitAlg = jwk["alg"] as? String
    if (explicitAlg != null) return explicitAlg

    val kty = jwk["kty"] as? String
        ?: throw InvalidData("JWK missing 'kty' field", className)
    val crv = jwk["crv"] as? String

    return when {
        kty.equals("OKP", ignoreCase = true) && crv.equals("Ed25519", ignoreCase = true) -> "EdDSA"
        kty.equals("EC", ignoreCase = true) && crv.equals("P-256", ignoreCase = true) -> "ES256"
        kty.equals("EC", ignoreCase = true) && crv.equals("P-384", ignoreCase = true) -> "ES384"
        kty.equals("EC", ignoreCase = true) && crv.equals("P-521", ignoreCase = true) -> "ES512"
        kty.equals("EC", ignoreCase = true) && crv.equals("secp256k1", ignoreCase = true) -> "ES256K"
        kty.equals("RSA", ignoreCase = true) -> "RS256"
        else -> throw InvalidData("Cannot determine algorithm from JWK (kty=$kty, crv=$crv)", className)
    }
}

private const val BASE58_BTCALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

fun encodeToMultibaseBase58btc(bytes: ByteArray): String {
    val leadingZeros = bytes.takeWhile { it == 0.toByte() }.count()
    var value = BigInteger(1, bytes)
    val base = BigInteger.valueOf(58)
    val sb = StringBuilder()
    while (value > BigInteger.ZERO) {
        val (quotient, remainder) = value.divideAndRemainder(base)
        sb.append(BASE58_BTCALPHABET[remainder.toInt()])
        value = quotient
    }
    repeat(leadingZeros) { sb.append(BASE58_BTCALPHABET[0]) }
    return "z" + sb.reverse().toString()
}

fun resolveJWSAlgorithm(didUrl: String, className: String = "Utils"): String {
    return try {
        val rawKey: PublicKey = DidPublicKeyResolver().resolve(didUrl.trimEnd('='), null)
        val jwsAlgorithm = when (rawKey) {
            is ECPublicKey -> {
                val curve = Curve.forECParameterSpec(rawKey.params)
                    ?: throw IllegalArgumentException("Unknown or unsupported EC curve parameters")

                when (curve) {
                    Curve.SECP256K1 -> JWSAlgorithm.ES256K
                    Curve.P_256 -> JWSAlgorithm.ES256
                    Curve.P_384 -> JWSAlgorithm.ES384
                    Curve.P_521 -> JWSAlgorithm.ES512
                    else -> throw IllegalArgumentException("Unsupported EC curve: ${curve.name}")
                }
            }

            is RSAPublicKey -> JWSAlgorithm.RS256

            else -> {
                if (rawKey.algorithm.equals(
                        "Ed25519",
                        ignoreCase = true
                    ) || rawKey.algorithm.equals("EdDSA", ignoreCase = true)
                ) {
                    JWSAlgorithm.EdDSA
                } else {
                    throw IllegalArgumentException("Unsupported key type: ${rawKey.javaClass.simpleName}")
                }
            }
        }

        jwsAlgorithm.name
    } catch (e: Exception) {
        throw InvalidData(
            message = "Unable to resolve a supported JWS algorithm for key",
            className = className,
            cause = e
        )
    }
}

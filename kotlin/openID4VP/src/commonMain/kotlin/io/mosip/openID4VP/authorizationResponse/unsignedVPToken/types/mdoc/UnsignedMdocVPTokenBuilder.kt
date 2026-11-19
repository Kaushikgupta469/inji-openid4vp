package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.MdocCredentialUtils.getMdocDocType
import io.mosip.openID4VP.common.MdocDeviceResponseUtils
import io.mosip.openID4VP.common.MdocCredentialUtils.extractMdocKeyReferenceAndAlg
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.createHashedDataItem
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.generateHash
import io.mosip.openID4VP.common.toJWKThumbprintBstr
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory


private const val className = "UnsignedMdocVPTokenBuilder"

internal class UnsignedMdocVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val responseUri: String,
    private val mdocGeneratedNonce: String,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {
    @JvmName("buildForPex")
    fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Map<String, ByteArray>, List<UnsignedVPToken>> {
        val uuidToDeviceAuthenticationBytes = mutableMapOf<String, ByteArray>()

        val sessionTranscript = encodeCbor(getSessionTranscript())
        val existingDocTypes = mutableSetOf<String>()

        val unsignedVPTokens = credentialInputDescriptorMappings.map { credentialInputDescriptorMapping ->
            buildPayloadAndUnsignedVPToken(
                credential = credentialInputDescriptorMapping.credential,
                sessionTranscript = sessionTranscript,
                uuidToDeviceAuthenticationBytes = uuidToDeviceAuthenticationBytes,
                setIdentifier = { identifier ->
                    credentialInputDescriptorMapping.identifier = identifier
                },
                existingDocTypes = existingDocTypes
            )
        }

        return Pair(uuidToDeviceAuthenticationBytes, unsignedVPTokens)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>
    ): Pair<Map<String, ByteArray>, List<UnsignedVPToken>> {
        val uuidToDeviceAuthenticationBytes = mutableMapOf<String, ByteArray>()

        val sessionTranscript = encodeCbor(getSessionTranscript())
        val existingDocTypes = mutableSetOf<String>()

        val unsignedVPTokens = credentialToCredentialQueryIdMappings.map { mapping ->
            buildPayloadAndUnsignedVPToken(
                credential = mapping.credential,
                sessionTranscript = sessionTranscript,
                uuidToDeviceAuthenticationBytes = uuidToDeviceAuthenticationBytes,
                setIdentifier = { identifier ->
                    mapping.identifier = identifier
                },
                existingDocTypes = existingDocTypes
            )
        }

        return Pair(uuidToDeviceAuthenticationBytes, unsignedVPTokens.toList())
    }

    private fun getSessionTranscript(): DataItem {
        val openId4VPHandover = MdocSpecVersionHandler.from(specVersion)
            .buildOpenID4VPHandover(
                authorizationRequest = authorizationRequest,
                mdocGeneratedNonce = mdocGeneratedNonce,
                responseUri = responseUri,
                walletConfig = walletConfig
            )
        val sessionTranscript = cborArrayOf(null, null, openId4VPHandover)
        return sessionTranscript
    }

    private fun buildPayloadAndUnsignedVPToken(
        credential: Any,
        sessionTranscript: ByteArray,
        uuidToDeviceAuthenticationBytes: MutableMap<String, ByteArray>,
        setIdentifier: (String) -> Unit,
        existingDocTypes: MutableSet<String>
    ): UnsignedVPToken {
        val docType = (getMdocDocType(credential, className))

        if (existingDocTypes.contains(docType)) {
            throw OpenID4VPExceptions.InvalidData(
                "Duplicate Mdoc Credentials with same doctype found",
                className
            )
        }
        existingDocTypes.add(docType)

        val identifier = UUIDGenerator.generateUUID()
        val (keyRef, alg) = extractMdocKeyReferenceAndAlg(credential as String, className)

        val bytesToSign = MdocDeviceResponseUtils.deviceAuthenticationDataToSign(sessionTranscript, docType, alg)
        uuidToDeviceAuthenticationBytes[identifier] = bytesToSign
        setIdentifier(identifier)

        return UnsignedVPToken(
            identifier,
            FormatType.MSO_MDOC,
            keyRef,
            alg,
            bytesToSign

        )
    }

    private sealed class MdocSpecVersionHandler {
        object Draft23 : MdocSpecVersionHandler()
        object SpecV1 : MdocSpecVersionHandler()

        companion object {
            fun from(specVersion: SpecVersion): MdocSpecVersionHandler {
                return if (specVersion == SpecVersion.V1) SpecV1 else Draft23
            }
        }

        fun buildOpenID4VPHandover(
            authorizationRequest: AuthorizationRequest,
            mdocGeneratedNonce: String,
            responseUri: String,
            walletConfig: WalletConfig
        ): DataItem {
            val handoverInfo = when (this) {
                is Draft23 -> {
                    val clientIdHash =
                        createHashedDataItem(authorizationRequest.clientId, mdocGeneratedNonce)
                    val responseUriHash = createHashedDataItem(responseUri, mdocGeneratedNonce)
                    cborArrayOf(clientIdHash, responseUriHash, authorizationRequest.nonce)
                }

                is SpecV1 -> {
                    val responseHandler = ResponseModeBasedHandlerFactory.get(
                        authorizationRequest.responseMode ?: ""
                    )
                    val verifierPublicKey = responseHandler.getVerifierPublicKeyForEncryption(
                        authorizationRequest, walletConfig
                    )
                    val thumbprintDataItem: DataItem? = verifierPublicKey?.let {
                        toJWKThumbprintBstr(it)
                    }

                    val openId4VPHandoverInfo: DataItem = cborArrayOf(
                        authorizationRequest.clientId,
                        authorizationRequest.nonce,
                        thumbprintDataItem,
                        responseUri
                    )
                    val openID4VPHandoverInfoBytes = (encodeCbor(openId4VPHandoverInfo))
                    val handoverInfoHash = ByteString(generateHash(openID4VPHandoverInfoBytes))
                    cborArrayOf("OpenID4VPHandover", handoverInfoHash)
                }
            }
            return handoverInfo
        }
    }
}

package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.constants.FormatType

internal class CredentialInputDescriptorMapping(
    val format: FormatType,
    val credential: Any,
    val inputDescriptorId: String
) : java.io.Serializable {
    // Optional Identifier - unique identifier for the credential, used for mapping to unsignedVpToken to its related VPTokenSigningResult
    // Example: UUID of the credential for SD-JWT, docType of the credential for mDoc
    var identifier: String? = null
    // Optional nested path - Pointer to the location of the credential within a VP
    // Example: for `ldp_vc` - "$.verifiableCredential[0]" -> the first credential in the verifiableCredential array of the VP Token contains the credential for the input descriptor id
    var nestedPath: String? = null
}


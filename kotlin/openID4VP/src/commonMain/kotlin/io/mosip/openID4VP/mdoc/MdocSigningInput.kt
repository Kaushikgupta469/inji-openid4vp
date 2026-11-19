package io.mosip.openID4VP.mdoc

/**
 * What the wallet signs for one document. Sign [dataToSign] with the private key matching
 * [holderKeyReference] (the credential's deviceKey as a base64url COSE_Key) using
 * [signatureAlgorithm] ("ES256" or "EdDSA"), and return the raw signature: r ‖ s for ES256.
 */
data class MdocSigningInput(
    val holderKeyReference: String,
    val signatureAlgorithm: String,
    val dataToSign: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MdocSigningInput) return false
        return holderKeyReference == other.holderKeyReference &&
            signatureAlgorithm == other.signatureAlgorithm &&
            dataToSign.contentEquals(other.dataToSign)
    }

    override fun hashCode(): Int {
        var result = holderKeyReference.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + dataToSign.contentHashCode()
        return result
    }
}

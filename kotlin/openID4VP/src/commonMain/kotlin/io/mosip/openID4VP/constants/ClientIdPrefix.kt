package io.mosip.openID4VP.constants

enum class ClientIdPrefix(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DECENTRALIZED_IDENTIFIER("decentralized_identifier"),
    X509_HASH("x509_hash");

    companion object {
        fun fromValue(value: String): ClientIdPrefix? {
            return entries.find { it.value == value }
        }

        // Returns null when Draft 23 defines no Client Identifier Scheme for the prefix
        fun toClientIdScheme(clientIdPrefix: ClientIdPrefix): String? {
            return when (clientIdPrefix) {
                PRE_REGISTERED -> ClientIdScheme.PRE_REGISTERED.value
                REDIRECT_URI -> ClientIdScheme.REDIRECT_URI.value
                DECENTRALIZED_IDENTIFIER -> ClientIdScheme.DID.value
                X509_HASH -> null
            }
        }
    }
}

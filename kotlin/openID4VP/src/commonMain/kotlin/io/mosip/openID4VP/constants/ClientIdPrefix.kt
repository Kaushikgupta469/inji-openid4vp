package io.mosip.openID4VP.constants

import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

enum class ClientIdPrefix(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DECENTRALIZED_IDENTIFIER("decentralized_identifier"),
    X509_HASH("x509_hash");

    companion object {
        fun fromValue(value: String): ClientIdPrefix? {
            return entries.find { it.value == value }
        }

        fun toClientIdScheme(clientIdPrefix: ClientIdPrefix): String {
            return when (clientIdPrefix) {
                PRE_REGISTERED -> ClientIdScheme.PRE_REGISTERED.value
                REDIRECT_URI -> ClientIdScheme.REDIRECT_URI.value
                DECENTRALIZED_IDENTIFIER -> ClientIdScheme.DID.value
                X509_HASH -> throw OpenID4VPExceptions.InvalidData(
                    "client_id_scheme is not supported for client_id_prefix ${X509_HASH.value}",
                    ClientIdPrefix::class.simpleName!!
                )
            }
        }
    }
}

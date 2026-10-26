package io.mosip.openID4VP.constants

enum class SignatureAlgorithm(val value: String) {
    EdDSA("EdDSA"),
    ES256("ES256");

    companion object {
        fun fromValue(value: String): SignatureAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}
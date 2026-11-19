package io.mosip.openID4VP.authorizationResponse.mdoc

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.toHex
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletConfig
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks the bytes of today's online mdoc output, built from the real test credential with
 * nothing mocked, so that sharing the DeviceAuthentication code with in-person presentation
 * cannot change what online verifiers receive.
 */
class MdocOnlineOutputGoldenJvmTest {

    private fun request() = AuthorizationDcqlRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = responseUrl,
        redirectUri = null,
        nonce = verifierNonce,
        walletNonce = null,
        state = null,
        clientMetadata = null,
        dcqlQuery = DCQLQuery(credentials = listOf(CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value)))
    )

    private fun dataToSign(specVersion: SpecVersion): String {
        val mapping = CredentialToCredentialQueryIdMapping(FormatType.MSO_MDOC, mdocCredential, "mobile-id")
        val builder = UnsignedMdocVPTokenBuilder(request(), specVersion, responseUrl, walletNonce, walletConfig)
        return builder.build(mutableListOf(mapping)).second.single().dataToSign.toHex()
    }

    @Test
    fun `draft 23 data to sign is unchanged`() {
        val expected =
            "846a5369676e61747572653143a10126405896d8185892847444657669636541757468656e7469636174696f6e83f6f6" +
            "8358206d64883bb228df2caa6c49dac1abe687f1db9209dd13594c200a04bbacc9d94e5820820f28ef68e7a7bb567ad2" +
            "84712295a02a74e63ee84f8c8126921024fe1eeaef7818474d31325a79774c786d4130506a51466576622f57513d3d75" +
            "6f72672e69736f2e31383031332e352e312e6d444cd81841a0"

        assertEquals(expected, dataToSign(SpecVersion.DRAFT_23))
    }

    @Test
    fun `spec V1 data to sign is unchanged`() {
        val expected =
            "846a5369676e61747572653143a1012640586cd8185868847444657669636541757468656e7469636174696f6e83f6f6" +
            "82714f70656e494434565048616e646f7665725820c38d74bb0ea0585e9853f4b9cc0bb2720471ac0139a849f317ecae" +
            "1d3ba6a2c6756f72672e69736f2e31383031332e352e312e6d444cd81841a0"

        assertEquals(expected, dataToSign(SpecVersion.V1))
    }

    @Test
    fun `device response for a fixed signature is unchanged`() {
        val mapping = CredentialToCredentialQueryIdMapping(FormatType.MSO_MDOC, mdocCredential, "mobile-id")
        mapping.identifier = "id-1"
        // any 64 bytes stand in for an ES256 signature; only the wrapping is locked here
        val signature = ByteArray(64) { it.toByte() }

        val result = MdocVPTokenBuilder().build(
            credentialToCredentialQueryIdMappings = listOf(mapping),
            unsignedVPTokenResult = Pair(emptyMap(), emptyList()),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signature))
        )

        val token = result.getValue("mobile-id").single() as MdocVPToken
        val expected =
            "o2ZzdGF0dXMAZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGRldmljZVNp" +
            "Z25lZKJqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd" +
            "Hh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P2puYW1lU3BhY2Vz2BhBoGxpc3N1ZXJTaWduZWSiamlzc3VlckF1" +
            "dGiEQ6EBJqEYIVkCADCCAfwwggGjAhQF2zbegdWq1XHLmdrVZZIORS_efDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCSU4x" +
            "CzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMQwwCgYDVQQLDANEQ1MxEDAOBgNVBAMM" +
            "B0NFUlRJRlkxIDAeBgkqhkiG9w0BCQEWEW1vc2lwcWFAZ21haWwuY29tMB4XDTI1MDIxMjEyMzE1N1oXDTI2MDIxMjEyMzE1" +
            "N1owgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEMMAoG" +
            "A1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTBZMBMGByqGSM49" +
            "AgEGCCqGSM49AwEHA0IABAcZXrsgNSABzg9o_dNKu6S2pXuJ3hgYlX162Ex56IUGDJZP_IlRCrEQPHZSSl53DwlpL4iHisAS" +
            "qFaRQiXAtqkwCgYIKoZIzj0EAwIDRwAwRAIgGI6B63QccJQ4B84hRjRGlRURJ5SSNTuf74w-nE8zqRACIA3diiD3VCA5G6jo" +
            "GeTSX-Xx79shhDrCmUHuj3Lk5uL1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5" +
            "cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggwUwjgySYg2DOdGY4" +
            "nNo0iwMhvWfX461qVPqRfzOSkLAGWCAqcNYwEHbJmU1HDkOtxjK_X-L6wsApZp6M68hP0409vANYIHvJF0gsS8tMyfvTgmIe" +
            "EeLIL-wx50tcOjkJNGJUB7eaAVggeYDGTfx8w7Sz2hIQvkZ1QhtrXskhDjZkS_cgN6HP18oEWCBeZlkW29iqUBLxAFlOfHrz" +
            "5qXioXKKaoyEEYI96YyKvwBYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm" +
            "6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VL" +
            "ZXmkAQIgASFYIHXTzp8Von2hagU3QkJVjUyInx0bVtJ_jBEGgdg9i8_xIlggcu55Afxk6PuLoyhqtNVMr_C2H2tumM4fKr-f" +
            "thKcg0dsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMzBUMTE6NTQ6MzdaaXZhbGlkRnJvbcB0MjAyNS0wNC0zMFQx" +
            "MTo1NDozN1pqdmFsaWRVbnRpbMB0MjAyNy0wNC0zMFQxMTo1NDozN1pYQMU-ji8KQVOtW-G8YJWadw4_ZSRpb56M4Xv8MUg9" +
            "ivRqV3VIJpJ5tB55onmNLrVOao0OunClNsBP7iNvX8P3d-BqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRo" +
            "ZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZh" +
            "bHVlajIwMjUtMDQtMzDYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJr" +
            "ZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMzAtMDQtMzDYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9A" +
            "bMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNS0w" +
            "NC0zMCwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMzAtMDQtMzB92BhYXaRoZGlnZXN0SUQBZnJh" +
            "bmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqOTI2" +
            "MTQ4MTAyNNgYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5n" +
            "X2NvdW50cnlsZWxlbWVudFZhbHVlYklO2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJ" +
            "ZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bd" +
            "U7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0" +
            "SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZB" +
            "Z2F0aGE"
        assertEquals(expected, token.base64EncodedDeviceResponse)
    }
}

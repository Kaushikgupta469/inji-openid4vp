package io.mosip.openID4VP.mdoc

import co.nstant.`in`.cbor.model.ByteString
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.toHex
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The DeviceResponse built from credentials signed by an independent test issuer (tuvali-iso-tools
 * generate_mdoc_response.py, cbor2 + cryptography), with the device key signing for real.
 * The last test writes the response to build/mdoc-proximity/ for verify_device_response.py.
 */
class MdocProximityVectorsJvmTest {

    private val vectors: JsonNode = ObjectMapper().readTree(
        checkNotNull(javaClass.getResource("/mdoc/proximity-vectors.json")) { "proximity-vectors.json missing" }
    )
    private val sessionTranscriptBytes = vectors.text("sessionTranscriptBytes").hexToBytes()
    private val deviceKey = p256PrivateKey(vectors.path("deviceKey").text("privateScalar"))

    private fun JsonNode.text(field: String): String = checkNotNull(get(field)) { "No $field in vectors" }.asText()

    private fun credential(document: String) = vectors.path(document).text("sharedCredential").hexToBytes()

    /** Signs like a wallet: ECDSA P-256 with SHA-256, returned as raw r ‖ s. */
    private fun signWithDeviceKey(input: MdocSigningInput): ByteArray {
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(deviceKey)
            update(input.dataToSign)
            sign()
        }
        return rawSignature(der)
    }

    private fun build(vararg documents: String, recorded: MutableList<MdocSigningInput> = mutableListOf()) =
        runSuspending {
            MdocProximity.buildDeviceResponse(sessionTranscriptBytes, documents.map(::credential)) { input ->
                recorded += input
                signWithDeviceKey(input)
            }
        }

    @Test
    fun `the device is asked to sign exactly the data computed independently for the mDL`() {
        val asked = mutableListOf<MdocSigningInput>()

        build("mdl", recorded = asked)

        assertEquals(vectors.path("mdl").text("dataToSign"), asked.single().dataToSign.toHex())
    }

    @Test
    fun `each of two documents gets its own data to sign`() {
        val asked = mutableListOf<MdocSigningInput>()

        build("mdl", "pid", recorded = asked)

        val expected = listOf("mdl", "pid").map { vectors.path(it).text("dataToSign") }
        assertEquals(expected, asked.map { it.dataToSign.toHex() })
    }

    @Test
    fun `the holder key reference is the device key from the MSO`() {
        val asked = mutableListOf<MdocSigningInput>()

        build("mdl", recorded = asked)

        val coseKey = vectors.path("deviceKey").text("coseKey")
        val reference = java.util.Base64.getUrlDecoder().decode(asked.single().holderKeyReference)
        assertEquals(coseKey, encodeCbor(decodeCbor(reference)).toHex())
    }

    @Test
    fun `issuerSigned in the response is the shared credential as passed in`() {
        val response = decodeCbor(build("mdl"))

        val issuerSigned = response["documents"].items().single()["issuerSigned"]
        assertEquals(vectors.path("mdl").text("sharedCredential"), encodeCbor(issuerSigned).toHex())
    }

    @Test
    fun `with a fixed signature the response is byte for byte the one built independently`() {
        // the same expected bytes are checked by the Swift library, so both platforms send the same response
        val fixed = vectors.path("withFixedSignature")
        val signature = fixed.text("signature").hexToBytes()

        val response = runSuspending {
            MdocProximity.buildDeviceResponse(sessionTranscriptBytes, listOf("mdl", "pid").map(::credential)) { signature }
        }

        assertEquals(fixed.text("mdlAndPidDeviceResponse"), response.toHex())
    }

    @Test
    fun `writes the response for the two documents for verify_device_response_py`() {
        val response = build("mdl", "pid")

        val out = File("build/mdoc-proximity/device-response.hex")
        out.parentFile.mkdirs()
        out.writeText(response.toHex())
        assertEquals(2, decodeCbor(response)["documents"].items().size)
    }

    private fun p256PrivateKey(scalarHex: String): ECPrivateKey {
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        val spec = ECPrivateKeySpec(BigInteger(1, scalarHex.hexToBytes()), parameters.getParameterSpec(ECParameterSpec::class.java))
        return KeyFactory.getInstance("EC").generatePrivate(spec) as ECPrivateKey
    }

    /** DER SEQUENCE { INTEGER r, INTEGER s } to 32-byte r ‖ 32-byte s. */
    private fun rawSignature(der: ByteArray): ByteArray {
        var offset = 2
        fun integer(): ByteArray {
            val length = der[offset + 1].toInt()
            val value = der.copyOfRange(offset + 2, offset + 2 + length)
            offset += 2 + length
            return value.dropWhile { it == 0.toByte() }.toByteArray().let { ByteArray(32 - it.size) + it }
        }
        return integer() + integer()
    }
}

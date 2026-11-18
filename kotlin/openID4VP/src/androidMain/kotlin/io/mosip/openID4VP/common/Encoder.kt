package io.mosip.openID4VP.common

import android.annotation.SuppressLint
import android.os.Build
import android.util.Base64.NO_PADDING
import android.util.Base64.NO_WRAP
import android.util.Base64.URL_SAFE
import android.util.Base64.encodeToString
import io.mosip.vercred.vcverifier.utils.BuildConfig.getVersionSDKInt
import java.util.Base64.getUrlEncoder

actual fun encodeToBase64Url(data: ByteArray): String {
    return if (getVersionSDKInt() >= Build.VERSION_CODES.O) {
            javaBase64UrlEncode(data)
        } else {
            androidBase64UrlEncode(data)
        }

}

@SuppressLint("NewApi")
private fun javaBase64UrlEncode(data: ByteArray): String =
    getUrlEncoder().withoutPadding().encodeToString(data)

private fun androidBase64UrlEncode(data: ByteArray): String {
    val base64 = encodeToString(data, URL_SAFE or NO_PADDING or NO_WRAP)
    return base64
}
package org.samfun.ktprd.utils

import org.samfun.ktvine.utils.KtvineException

/**
 * Base class for everything ktprd throws.
 *
 * It extends ktvine's [KtvineException] so a caller — or ktvine's own serve routing — can catch
 * the whole family of DRM errors from either CDM with one handler.
 */
public open class KtprdException(message: String) : KtvineException(message)

/** A PlayReady device (`.prd`) blob is malformed or of an unsupported version. */
public class InvalidPrdException(message: String) : KtprdException(message)

/** A `CERT` certificate is malformed, or its signature does not verify. */
public class InvalidCertificateException(message: String) : KtprdException(message)

/** A `CHAI` certificate chain is malformed, or the chain does not verify end to end. */
public class InvalidCertificateChainException(message: String) : KtprdException(message)

/** An XMR license is malformed, or does not match the device it was issued to. */
public class InvalidXmrLicenseException(message: String) : KtprdException(message)

/** An XMR license's integrity CMAC does not match its content. */
public class XmrSignatureException(message: String) : KtprdException(message)

/** A `WRMHEADER` is malformed, absent, or of an unsupported version. */
public class InvalidWrmHeaderException(message: String) : KtprdException(message)

/** A content key's checksum could not be checked, or did not match the header. */
public class InvalidChecksumException(message: String) : KtprdException(message)

/** A SOAP envelope is malformed, or is not the message the protocol expects. */
public class InvalidSoapMessageException(message: String) : KtprdException(message)

/** The license server returned a fault. */
public class PlayreadyServerException(message: String, public val statusCode: Int?) : KtprdException(message)

/** A license response is malformed, or its signature does not verify. */
public class InvalidLicenseResponseException(message: String) : KtprdException(message)

/** A revocation list is malformed, or its signature does not verify. */
public class InvalidRevocationListException(message: String) : KtprdException(message)

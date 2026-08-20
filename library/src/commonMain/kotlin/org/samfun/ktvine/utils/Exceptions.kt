package org.samfun.ktvine.utils

/** Base class for Ktvine library exceptions. */
public open class KtvineException(message: String) : Exception(message)

/** Too many sessions are open simultaneously. */
public class TooManySessionsException(message: String) : KtvineException(message)
/** Session id is invalid or not found. */
public class InvalidSessionException(message: String) : KtvineException(message)
/** General decoding/parsing failure. */
public class DecodeException(message: String) : KtvineException(message)
/** Signature or MAC verification failed. */
public class SignatureMismatchException(message: String) : KtvineException(message)
/** Init data or PSSH is missing/invalid for a request. */
public class InvalidInitDataException(message: String) : KtvineException(message)
/** The requested license type is not a valid value. */
public class InvalidLicenseTypeException(message: String) : KtvineException(message)
/** The license message is missing, empty, or not a LICENSE. */
public class InvalidLicenseMessageException(message: String) : KtvineException(message)
/** No request context is stored for this session, so a license cannot be parsed. */
public class InvalidContextException(message: String) : KtvineException(message)
/** No license has been parsed for this session, so no keys are available. */
public class NoKeysLoadedException(message: String) : KtvineException(message)
/** A remote CDM's device information does not match the local device. */
public class DeviceMismatchException(message: String) : KtvineException(message)
/** Invalid/unsupported value encountered. */
public class ValueException(message:String): KtvineException(message)
/** MP4 PSSH box parsing error. */
public class InvalidBoxException(message:String): KtvineException(message)

/**
 * Require an optional protobuf field that the protocol makes mandatory.
 *
 * Everything these guard is attacker-controlled input from a license server, so a missing
 * field must surface as a [DecodeException] rather than a platform NullPointerException.
 */
internal fun <T : Any> T?.orDecodeError(field: String): T =
    this ?: throw DecodeException("Malformed message: required field '$field' is missing")

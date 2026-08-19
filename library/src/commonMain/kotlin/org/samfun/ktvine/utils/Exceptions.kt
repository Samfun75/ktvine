package org.samfun.ktvine.utils

/** Base class for Ktvine library exceptions. */
open class KtvineException(message: String) : Exception(message)

/** Too many sessions are open simultaneously. */
class TooManySessionsException(message: String) : KtvineException(message)
/** Session id is invalid or not found. */
class InvalidSessionException(message: String) : KtvineException(message)
/** General decoding/parsing failure. */
class DecodeException(message: String) : KtvineException(message)
/** Signature or MAC verification failed. */
class SignatureMismatchException(message: String) : KtvineException(message)
/** Init data or PSSH is missing/invalid for a request. */
class InvalidInitDataException(message: String) : KtvineException(message)
/** The requested license type is not a valid value. */
class InvalidLicenseTypeException(message: String) : KtvineException(message)
/** The license message is missing, empty, or not a LICENSE. */
class InvalidLicenseMessageException(message: String) : KtvineException(message)
/** No request context is stored for this session, so a license cannot be parsed. */
class InvalidContextException(message: String) : KtvineException(message)
/** No license has been parsed for this session, so no keys are available. */
class NoKeysLoadedException(message: String) : KtvineException(message)
/** A remote CDM's device information does not match the local device. */
class DeviceMismatchException(message: String) : KtvineException(message)
/** Invalid/unsupported value encountered. */
class ValueException(message:String): KtvineException(message)
/** MP4 PSSH box parsing error. */
class InvalidBoxException(message:String): KtvineException(message)

/**
 * Require an optional protobuf field that the protocol makes mandatory.
 *
 * Everything these guard is attacker-controlled input from a license server, so a missing
 * field must surface as a [DecodeException] rather than a platform NullPointerException.
 */
internal fun <T : Any> T?.orDecodeError(field: String): T =
    this ?: throw DecodeException("Malformed message: required field '$field' is missing")

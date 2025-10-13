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
/** License message was empty or of wrong type. */
class InvalidLicenseTypeException(message: String) : KtvineException(message)
/** Invalid/unsupported value encountered. */
class ValueException(message:String): KtvineException(message)
/** MP4 PSSH box parsing error. */
class InvalidBoxException(message:String): KtvineException(message)

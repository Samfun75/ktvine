package org.samfun.ktvine.utils

open class KtvineException(message: String) : Exception(message)

class TooManySessionsException(message: String) : KtvineException(message)
class InvalidSessionException(message: String) : KtvineException(message)
class DecodeException(message: String) : KtvineException(message)
class SignatureMismatchException(message: String) : KtvineException(message)
class InvalidInitDataException(message: String) : KtvineException(message)
class InvalidLicenseTypeException(message: String) : KtvineException(message)
class ValueException(message:String): KtvineException(message)
class InvalidBoxException(message:String): KtvineException(message)

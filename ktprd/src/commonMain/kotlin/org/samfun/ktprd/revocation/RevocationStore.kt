package org.samfun.ktprd.revocation

import okio.FileSystem
import okio.Path
import okio.Path.Companion.toPath

/**
 * Where revocation data persists between sessions.
 *
 * A license challenge advertises which revocation lists the client already holds and at what
 * version; a server may then send newer ones back, which the client is expected to keep. There is
 * no multiplatform notion of a user data directory, so ktprd asks the caller where that goes
 * instead of guessing — the same reason ktvine's device loading takes an explicit `FileSystem`.
 */
public interface RevocationStore {
    public suspend fun read(name: String): ByteArray?

    public suspend fun write(name: String, data: ByteArray)

    public companion object {
        /** A store that keeps nothing, so every challenge advertises version 0. */
        public val None: RevocationStore = InMemoryRevocationStore()
    }
}

/** Keeps revocation data for the lifetime of this object only. */
public class InMemoryRevocationStore : RevocationStore {
    private val entries = mutableMapOf<String, ByteArray>()

    override suspend fun read(name: String): ByteArray? = entries[name]

    override suspend fun write(name: String, data: ByteArray) {
        entries[name] = data
    }
}

/**
 * Keeps revocation data as files under [directory].
 *
 * [fileSystem] is explicit because `FileSystem.SYSTEM` is not part of okio's common API; pass it
 * from a platform source set, or a fake in tests.
 */
public class FileRevocationStore(private val directory: Path, private val fileSystem: FileSystem) : RevocationStore {
    public constructor(directory: String, fileSystem: FileSystem) : this(directory.toPath(), fileSystem)

    override suspend fun read(name: String): ByteArray? {
        val path = directory / name
        if (!fileSystem.exists(path)) return null
        return fileSystem.read(path) { readByteArray() }
    }

    override suspend fun write(name: String, data: ByteArray) {
        fileSystem.createDirectories(directory)
        fileSystem.write(directory / name) { write(data) }
    }
}

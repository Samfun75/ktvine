package org.samfun.ktvine

/**
 * Loads test fixtures from the test classpath (`src/commonTest/resources`).
 *
 * The Widevine device fixtures under `device/` are real provisioning material and are
 * git-ignored, so they are absent in most checkouts; [orSkip] reports that explicitly
 * rather than letting a test silently pass.
 */
object TestFixtures {

    const val ROOT: String = "library/src/commonTest/resources"

    fun readOrNull(path: String): ByteArray? =
        TestFixtures::class.java
            .getResourceAsStream("/$path")
            ?.use { it.readBytes() }

    fun read(path: String): ByteArray =
        readOrNull(path) ?: error("Missing test fixture '$path'; expected it at $ROOT/$path")

    fun readText(path: String): String = read(path).decodeToString()

    /** Returns the fixture, or `null` after logging why the calling test is being skipped. */
    fun orSkip(path: String): ByteArray? {
        val data = readOrNull(path)
        if (data == null) {
            println("SKIP: test fixture '$path' is not present. Supply it at $ROOT/$path to run this test.")
        }
        return data
    }
}

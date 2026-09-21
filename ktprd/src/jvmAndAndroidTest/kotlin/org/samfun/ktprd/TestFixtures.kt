package org.samfun.ktprd

/**
 * Loads test fixtures from the test classpath.
 *
 * Paths are relative to [ROOT], which ktprd's build wires in as a test-resource directory so the
 * PlayReady devices are not duplicated into a second secret store. That material is git-ignored,
 * so a fresh checkout has none of it; [orSkip] is how a test says so out loud instead of quietly
 * passing on an empty input.
 */
object TestFixtures {
    const val ROOT: String = "ktvine/src/commonTest/resources"

    fun readOrNull(path: String): ByteArray? = TestFixtures::class.java
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

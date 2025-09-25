package org.samfun.ktvine

import kotlin.test.Test

class FibiTest {

    @Test
    fun `can run PSSH`() {
        val rawData =
            "AAAAoXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIEIARIQuLuP/+zYM2Ga0s2MA9iIKBoIY2FzdGxhYnMiWGV5SmhjM05sZEVsa0lqb2laRGhoTURoaU5HVXpaamxoTTJVM01qZzRPVGRpWlRNNU5ETXdaV05oTURBaUxDSjJZWEpwWVc1MFNXUWlPaUpoZG10bGVTSjkyB2RlZmF1bHQ="

        PSSH(rawData).main()
    }
}
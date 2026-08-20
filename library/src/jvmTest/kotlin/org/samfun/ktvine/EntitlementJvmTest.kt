package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.core.Key
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.crypto.aesCbcEncryptNoPadding
import org.samfun.ktvine.crypto.pkcs7Pad
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.WidevinePsshData
import org.samfun.ktvine.utils.InvalidInitDataException
import org.samfun.ktvine.utils.NoKeysLoadedException
import org.samfun.ktvine.utils.ValueException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.uuid.Uuid

class EntitlementJvmTest {

    private val WIDEVINE_UUID: Uuid = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    private val entitlementKid: Uuid = Uuid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    private val contentKid: Uuid = Uuid.parse("11111111-2222-3333-4444-555555555555")
    private val entitlementKey = ByteArray(16) { (it + 1).toByte() }
    private val contentKey = ByteArray(16) { (0xF0 - it).toByte() }
    private val iv = ByteArray(16) { (it * 3).toByte() }

    private fun cdm() = Cdm(DeviceTypes.ANDROID, ClientIdentification(), ByteArray(0))

    private val entitlementKeys = listOf(
        Key(License.KeyContainer.KeyType.ENTITLEMENT, entitlementKid, entitlementKey),
    )

    /** Wrap [contentKey] the way a packager would, so the unwrap has something real to undo. */
    private suspend fun entitledPssh(): PSSH {
        val wrapped = aesCbcEncryptNoPadding(entitlementKey, iv, pkcs7Pad(contentKey))
        val header = WidevinePsshData(
            type = WidevinePsshData.Type.ENTITLED_KEY,
            entitled_keys = listOf(
                WidevinePsshData.EntitledKey(
                    entitlement_key_id = entitlementKid.toByteArray().toByteString(),
                    key_id = contentKid.toByteArray().toByteString(),
                    key = wrapped.toByteString(),
                    iv = iv.toByteString(),
                ),
            ),
        )
        return PSSH.new(systemId = WIDEVINE_UUID, initData = header)
    }

    @Test
    fun `test entitled keys are unwrapped with the matching entitlement key`() {
        runBlocking {
            val keys = Cdm.unwrapEntitledKeys(entitlementKeys, entitledPssh())

            assertEquals(1, keys.size)
            assertEquals(contentKid, keys[0].kid)
            assertEquals(License.KeyContainer.KeyType.CONTENT, keys[0].type)
            assertContentEquals(contentKey, keys[0].key, "the unwrapped key must match the original")
        }
    }

    @Test
    fun `test entitlement unwrapping needs a loaded entitlement key`() {
        runBlocking {
            val cdm = cdm()
            val sessionId = cdm.open()
            assertFailsWith<NoKeysLoadedException> {
                cdm.getKeysFromEntitlement(sessionId, entitledPssh())
            }
        }
    }

    @Test
    fun `test a mismatched entitlement key id is rejected`() {
        runBlocking {
            val wrongKey = listOf(
                Key(License.KeyContainer.KeyType.ENTITLEMENT, Uuid.fromLongs(0, 99), entitlementKey),
            )
            assertFailsWith<ValueException> { Cdm.unwrapEntitledKeys(wrongKey, entitledPssh()) }
        }
    }

    @Test
    fun `test a pssh without entitled keys is rejected`() {
        runBlocking {
            val plain = PSSH.new(
                systemId = WIDEVINE_UUID,
                initData = WidevinePsshData(key_ids = listOf(contentKid.toByteArray().toByteString())),
            )
            assertFailsWith<InvalidInitDataException> {
                Cdm.unwrapEntitledKeys(entitlementKeys, plain)
            }
        }
    }
}

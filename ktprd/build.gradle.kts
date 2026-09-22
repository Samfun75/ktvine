import com.android.build.api.dsl.androidLibrary
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.dokka)
}

group = "io.github.samfun75"
version = libs.versions.ktvine.get()

// Published artifact name, and what the Dokka site calls this module.
val artifactId = "ktprd"

kotlin {
    applyDefaultHierarchyTemplate()

    explicitApi()
    jvmToolchain(21)

    // Kotlin's own, not binary-compatibility-validator: that one cannot read class file 67.
    @OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)
    abiValidation {
    }

    jvm {
        compilations.configureEach {
            compileTaskProvider.configure {
                compilerOptions.jvmTarget.set(JvmTarget.JVM_11)
            }
        }
    }

    androidLibrary {
        namespace = "io.github.samfun75.ktprd"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withHostTestBuilder {}.configure {}

        compilations.configureEach {
            compileTaskProvider.configure {
                compilerOptions.jvmTarget.set(JvmTarget.JVM_11)
            }
        }
    }

    iosX64()
    iosArm64()
    iosSimulatorArm64()
    linuxX64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                // PSSH/PlayReady-Object framing, the UTF-16LE codec, GUID helpers, AES-CMAC and
                // the exception base are all shared with the Widevine side rather than forked.
                api(project(":ktvine"))
                // :library scopes cryptography as `implementation`, so its types are not on our
                // classpath through that dependency.
                implementation(libs.bundles.cryptography)
                // P-256 point arithmetic has no provider on any target; see crypto/P256.kt.
                implementation(libs.bignum)
                implementation(libs.coroutines.core)
                implementation(libs.kermit)
                implementation(libs.xmlutil.core)
            }
        }
        val commonTest by getting {
            // The PlayReady device fixtures are real provisioning material and git-ignored; they
            // are read from where they already live rather than copied into a second secret store.
            resources.srcDir(rootProject.file("ktvine/src/commonTest/resources"))

            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.coroutines.test)
                implementation(libs.bundles.cryptography)
            }
        }
        // Shared by the two JVM-family test source sets so fixture loading is written once.
        val jvmAndAndroidTest by creating {
            dependsOn(commonTest)
        }
        val jvmTest by getting {
            dependsOn(jvmAndAndroidTest)
        }
        val androidHostTest by getting {
            dependsOn(jvmAndAndroidTest)
        }
    }
}

// Integration tests talk to Microsoft's public PlayReady test server, so they are opt-in.
tasks.named<Test>("jvmTest") {
    filter {
        excludeTestsMatching("org.samfun.ktprd.*IntegrationTest")
        isFailOnNoMatchingTests = false
    }
}

tasks.register<Test>("integrationTest") {
    group = "verification"
    description = "Runs tests that require network access to a live PlayReady license server."

    val jvmTest = tasks.named<Test>("jvmTest").get()
    testClassesDirs = jvmTest.testClassesDirs
    classpath = jvmTest.classpath
    dependsOn("jvmTestClasses")

    filter {
        includeTestsMatching("org.samfun.ktprd.*IntegrationTest")
        isFailOnNoMatchingTests = false
    }

    outputs.upToDateWhen { false }
    testLogging {
        showStandardStreams = true
    }
}

// Nothing else builds the metadata artifact publishing depends on.
tasks.named("check") {
    dependsOn("compileCommonMainKotlinMetadata")
}

// Pinned to the coordinate so a future project rename cannot silently move the doc URLs.
dokka {
    moduleName.set(artifactId)
    modulePath.set(artifactId)
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true)

    if (System.getenv("PUBLISH") != null) {
        signAllPublications()
    }

    coordinates(group.toString(), artifactId, version.toString())

    pom {
        name = artifactId
        description = "Kotlin Multiplatform PlayReady CDM: devices, certificate chains, XMR licenses and content keys"
        inceptionYear = "2025"
        url = "https://github.com/samfun75/ktvine/"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                id = "Samfun75"
                name = "Samfun"
                url = "https://github.com/Samfun75/"
            }
        }
        scm {
            url = "https://github.com/samfun75/ktvine/"
            connection = "scm:git:git://github.com/samfun75/ktvine.git"
            developerConnection = "scm:git:ssh://git@github.com/samfun75/ktvine.git"
        }
    }
}

import com.android.build.api.dsl.androidLibrary
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.wire)
}

group = "io.github.samfun75"
version = "0.0.3"

kotlin {
    applyDefaultHierarchyTemplate()

    jvm {
        wire.kotlin {
            android = false
        }
    }

    androidLibrary {
        namespace = "io.github.samfun75.ktvine"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withJava() // enable java compilation support
        withHostTestBuilder {}.configure {}
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }

        compilations.configureEach {
            compileTaskProvider.configure {
                compilerOptions.jvmTarget.set(JvmTarget.JVM_11)
            }
        }

        wire.kotlin {
            android = true
        }
    }
//    iosX64()
//    iosArm64()
//    iosSimulatorArm64()
//    linuxX64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                //put your multiplatform dependencies here
                api(libs.wire.runtime)
                implementation(libs.bundles.cryptography)
                implementation(libs.kermit)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.coroutines.core)
            }
        }
    }
}

wire {
    sourcePath {
        srcDirs("src/commonMain/proto")
    }

    kotlin {
        buildersOnly = true
        rpcRole = "server"
        rpcCallStyle = "suspending"
    }
}

mavenPublishing {
    publishToMavenCentral()

    if (System.getenv("PUBLISH") != null) {
        println("✅ Signing all publications.")
        signAllPublications()
    } else {
        println("⚠️ Skipping signing (JitPack or no signing keys).")
    }

    coordinates(group.toString(), "ktvine", version.toString())

    pom {
        name = "ktvine"
        description = "A KMP library for widevine DRM ported from python lib pywidevine"
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

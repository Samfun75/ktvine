import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.dokka)
}

group = "io.github.samfun75"
version = libs.versions.ktvine.get()

kotlin {
    applyDefaultHierarchyTemplate()

    explicitApi()

    // JVM only: Ktor's server engines do not span the six targets the client does.
    jvm {
        compilations.configureEach {
            compileTaskProvider.configure {
                compilerOptions.jvmTarget.set(JvmTarget.JVM_11)
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":ktprd"))
                // Routing only: the caller brings the engine, mirroring how :ktprd-remote takes a client.
                api(libs.ktor.server.core)
                implementation(libs.serialization.json)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.coroutines.test)
                implementation(libs.bundles.cryptography)
                implementation(libs.ktor.server.test.host)
                implementation(libs.ktor.client.core)
                // Cross-testing this server against ktprd's own client.
                implementation(project(":ktprd-remote"))
            }
        }
    }
}

mavenPublishing {
    publishToMavenCentral()

    if (System.getenv("PUBLISH") != null) {
        signAllPublications()
    }

    coordinates(group.toString(), "ktprd-serve", version.toString())

    pom {
        name = "ktprd-serve"
        description = "Ktor routing that serves a ktprd PlayReady CDM over pyplayready's serve protocol"
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

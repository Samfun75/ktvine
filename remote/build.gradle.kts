import com.android.build.api.dsl.androidLibrary
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.dokka)
}

group = "io.github.samfun75"
version = libs.versions.ktvine.get()

kotlin {
    applyDefaultHierarchyTemplate()

    explicitApi()

    compilerOptions {
        optIn.addAll(
            "kotlin.uuid.ExperimentalUuidApi",
            "kotlin.time.ExperimentalTime",
        )
    }

    jvm()

    androidLibrary {
        namespace = "io.github.samfun75.ktvine.remote"
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
                api(project(":library"))
                // Only the engine-agnostic client: the caller supplies the HttpClient, so
                // this module never picks an engine on their behalf.
                api(libs.ktor.client.core)
                // Runtime JSON only — no @Serializable classes, so no compiler plugin.
                implementation(libs.serialization.json)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.coroutines.test)
                implementation(libs.ktor.client.mock)
            }
        }
    }
}

// Nothing else builds the metadata artifact publishing depends on.
tasks.named("check") {
    dependsOn("compileCommonMainKotlinMetadata")
}

mavenPublishing {
    publishToMavenCentral()

    if (System.getenv("PUBLISH") != null) {
        signAllPublications()
    }

    coordinates(group.toString(), "ktvine-remote", version.toString())

    pom {
        name = "ktvine-remote"
        description = "Ktor-based client for a pywidevine-compatible remote CDM server"
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

plugins {
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlinMultiplatform) apply  false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.wire).apply(false)
    alias(libs.plugins.ktlint) apply false
    // Applied here, not `apply false`: the root project is what aggregates each module's
    // docs into one site. Without it only :library would be documented.
    alias(libs.plugins.dokka)
}

subprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
        // Wire's generated protobuf models are not ours to format.
        filter {
            exclude { "generated" in it.file.path }
        }
    }
}

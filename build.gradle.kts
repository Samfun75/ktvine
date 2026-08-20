plugins {
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlinMultiplatform) apply  false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.wire).apply(false)
    alias(libs.plugins.binary.compatibility.validator)
    alias(libs.plugins.ktlint) apply false
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

apiValidation {
    // Wire-generated protobuf models are not hand-written API; tracking them would make
    // every schema regeneration look like an ABI break.
    ignoredPackages.add("org.samfun.ktvine.proto")

    // The JVM dump alone would miss anything that only exists on the native targets.
    @OptIn(kotlinx.validation.ExperimentalBCVApi::class)
    klib {
        enabled = true
    }
}

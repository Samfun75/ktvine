pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ktvine"
include(":ktvine")
include(":ktvine-remote")
include(":ktvine-serve")
include(":ktprd")
include(":ktprd-remote")
include(":ktprd-serve")

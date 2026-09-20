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
include(":library")
include(":remote")
include(":serve")
include(":ktprd")
include(":ktprd-remote")
include(":ktprd-serve")

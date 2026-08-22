// Backstage for Android.
//
// A separate Gradle build rather than part of the pnpm workspace, because it is a
// separate toolchain: nothing here is reachable from `pnpm -r build`, and pretending
// otherwise would mean a web CI job that fails for want of an Android SDK.
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

rootProject.name = "backstage"
include(":app")

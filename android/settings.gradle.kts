pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
                includeGroupByRegex("com\\.google(\\..*)?")
            }
        }
        mavenCentral {
            content {
                includeGroupByRegex("org\\.jetbrains(\\..*)?")
                includeGroupByRegex("org\\.jetbrains\\.kotlin(\\..*)?")
                includeGroupByRegex("com\\.google\\.devtools\\.ksp(\\..*)?")
            }
        }
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
                includeGroupByRegex("com\\.google(\\..*)?")
            }
        }
        mavenCentral {
            content {
                excludeGroupByRegex("com\\.android(\\..*)?")
                excludeGroupByRegex("androidx(\\..*)?")
            }
        }
    }
}

rootProject.name = "KurdistanVPN"

include(
    ":app",
    ":core:model",
    ":core:ui",
    ":domain",
    ":core:native-api",
    ":core:native-jni",
    ":data:metadata",
    ":data:secure",
    ":data:settings",
    ":data:protected-state",
    ":platform:import",
    ":runtime:api",
    ":runtime:android",
    ":feature:home",
    ":feature:profiles",
    ":feature:settings-recovery",
    ":feature:diagnostics-about",
    ":benchmark",
    ":test:fixtures",
)

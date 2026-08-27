import java.util.Locale
import java.util.Properties
import org.gradle.api.tasks.Exec

plugins {
    alias(libs.plugins.android.library)
}

val repositoryRoot = rootProject.projectDir.parentFile
val generatedGoRoot = layout.buildDirectory.dir("generated/phase9Go")

android {
    namespace = "org.kurdistanvpn.core.nativejni"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        minSdk = 26
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=c++_static"
            }
        }
    }
    buildTypes {
        debug {
            ndk {
                abiFilters += setOf("arm64-v8a", "x86_64")
            }
            externalNativeBuild.cmake {
                abiFilters += setOf("arm64-v8a", "x86_64")
                arguments += "-DKVPN_GO_BRIDGE_ROOT=${generatedGoRoot.get().asFile.resolve("debug")}"
            }
        }
        create("internal") {
            // Do not initWith(debug): AGP shares the external-native argument
            // collection and the internal bridge root then contaminates Debug.
            ndk {
                abiFilters += setOf("arm64-v8a", "x86_64")
            }
            matchingFallbacks += listOf("debug")
            externalNativeBuild.cmake {
                abiFilters += setOf("arm64-v8a", "x86_64")
                arguments += "-DKVPN_GO_BRIDGE_ROOT=${generatedGoRoot.get().asFile.resolve("internal")}"
            }
        }
        release {
            ndk {
                abiFilters += "arm64-v8a"
            }
            externalNativeBuild.cmake {
                abiFilters += "arm64-v8a"
                arguments += "-DKVPN_GO_BRIDGE_ROOT=${generatedGoRoot.get().asFile.resolve("release")}"
            }
        }
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":core:native-api"))
}

fun ndkHostTag(): String =
    when {
        System.getProperty("os.name").startsWith("Windows", ignoreCase = true) -> "windows-x86_64"
        System.getProperty("os.name").startsWith("Mac", ignoreCase = true) -> "darwin-x86_64"
        else -> "linux-x86_64"
    }

fun clangExecutable(target: String): File {
    val suffix = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) ".cmd" else ""
    val localProperties = rootProject.file("local.properties")
    val configuredSdk = if (localProperties.isFile) {
        Properties().apply { localProperties.inputStream().use(::load) }.getProperty("sdk.dir")
    } else {
        null
    }
    val sdkDirectory = File(
        configuredSdk
            ?: System.getenv("ANDROID_HOME")
            ?: System.getenv("ANDROID_SDK_ROOT")
            ?: error("Android SDK path is not configured"),
    )
    return sdkDirectory
        .resolve("ndk/${android.ndkVersion}")
        .resolve("toolchains/llvm/prebuilt/${ndkHostTag()}/bin/${target}-linux-android26-clang$suffix")
}

data class AndroidGoAbi(
    val androidAbi: String,
    val goArch: String,
    val clangTarget: String,
)

val androidGoAbis = listOf(
    AndroidGoAbi("arm64-v8a", "arm64", "aarch64"),
    AndroidGoAbi("x86_64", "amd64", "x86_64"),
)

fun registerGoBridge(buildType: String, internalTrust: Boolean, abi: AndroidGoAbi) =
    tasks.register<Exec>(
        "build${buildType.replaceFirstChar { it.titlecase(Locale.ROOT) }}" +
            "${abi.androidAbi.replace("_", "").replace("-", "").replaceFirstChar { it.titlecase(Locale.ROOT) }}GoBridge",
    ) {
        group = "build"
        description = "Builds the bounded Go c-shared bridge for $buildType/${abi.androidAbi}."
        val outputDirectory = generatedGoRoot.get().asFile.resolve("$buildType/${abi.androidAbi}")
        // Configuration and task-graph inspection must never create build output.
        doFirst { check(outputDirectory.exists() || outputDirectory.mkdirs()) }
        val output = outputDirectory.resolve("libkurdistan_bridge.so")
        val header = outputDirectory.resolve("libkurdistan_bridge.h")
        inputs.files(
            fileTree(repositoryRoot.resolve("cmd/kandroidbridge")) { include("**/*.go") },
            fileTree(repositoryRoot.resolve("internal")) { include("**/*.go") },
            repositoryRoot.resolve("go.mod"),
            repositoryRoot.resolve("go.sum"),
        )
        outputs.files(output, header)
        workingDir(repositoryRoot)
        environment(
            "GOOS" to "android",
            "GOARCH" to abi.goArch,
            "CGO_ENABLED" to "1",
            "CC" to clangExecutable(abi.clangTarget).absolutePath,
        )
        val command = mutableListOf(
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-buildid= -B=none -extldflags=-Wl,--build-id=none,-soname,libkurdistan_bridge.so",
            "-buildmode=c-shared",
        )
        if (internalTrust) {
            command += listOf("-tags", "phase9internal")
        }
        command += listOf("-o", output.absolutePath, "./cmd/kandroidbridge")
        commandLine(command)
    }

val bridgeTasks = mapOf(
    "debug" to androidGoAbis.map { registerGoBridge("debug", internalTrust = false, it) },
    "internal" to androidGoAbis.map { registerGoBridge("internal", internalTrust = true, it) },
    "release" to androidGoAbis
        .filter { it.androidAbi == "arm64-v8a" }
        .map { registerGoBridge("release", internalTrust = false, it) },
)

val requestedNativeBuildTypes = gradle.startParameter.taskNames.map(String::lowercase)
val requestsInternalNative = requestedNativeBuildTypes.any { "internal" in it }
val requestsReleaseNative = requestedNativeBuildTypes.any { "release" in it }

tasks.configureEach {
    val lowerName = name.lowercase(Locale.ROOT)
    bridgeTasks.forEach { (buildType, buildTypeBridgeTasks) ->
        val cmakeConfigurationMatches = lowerName.contains(buildType) ||
            (lowerName.contains("relwithdebinfo") &&
                ((buildType == "internal" && requestsInternalNative) ||
                    (buildType == "release" && requestsReleaseNative)))
        if (
            cmakeConfigurationMatches &&
            // Kotlin/manifest/host-unit compilation does not consume the Go shared library.
            // Every native configure/build still requires the exact ABI bridge before CMake.
            (lowerName.contains("configurecmake") || lowerName.contains("buildcmake"))
        ) {
            dependsOn(buildTypeBridgeTasks)
        }
    }
}

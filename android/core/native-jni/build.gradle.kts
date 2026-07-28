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
        ndk {
            abiFilters += "arm64-v8a"
        }
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=c++_static"
            }
        }
    }
    buildTypes {
        debug {
            externalNativeBuild.cmake.arguments +=
                "-DKVPN_GO_BRIDGE_SO=${generatedGoRoot.get().asFile.resolve("debug/arm64-v8a/libkurdistan_bridge.so")}"
        }
        create("internal") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            externalNativeBuild.cmake.arguments +=
                "-DKVPN_GO_BRIDGE_SO=${generatedGoRoot.get().asFile.resolve("internal/arm64-v8a/libkurdistan_bridge.so")}"
        }
        release {
            externalNativeBuild.cmake.arguments +=
                "-DKVPN_GO_BRIDGE_SO=${generatedGoRoot.get().asFile.resolve("release/arm64-v8a/libkurdistan_bridge.so")}"
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

fun clangExecutable(): File {
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
        .resolve("toolchains/llvm/prebuilt/${ndkHostTag()}/bin/aarch64-linux-android26-clang$suffix")
}

fun registerGoBridge(buildType: String, internalTrust: Boolean) =
    tasks.register<Exec>("build${buildType.replaceFirstChar { it.titlecase(Locale.ROOT) }}GoBridge") {
        group = "build"
        description = "Builds the bounded Go c-shared bridge for $buildType."
        val outputDirectory = generatedGoRoot.get().asFile.resolve("$buildType/arm64-v8a")
        check(outputDirectory.exists() || outputDirectory.mkdirs())
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
            "GOARCH" to "arm64",
            "CGO_ENABLED" to "1",
            "CC" to clangExecutable().absolutePath,
        )
        val command = mutableListOf(
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-buildmode=c-shared",
        )
        if (internalTrust) {
            command += listOf("-tags", "phase9internal")
        }
        command += listOf("-o", output.absolutePath, "./cmd/kandroidbridge")
        commandLine(command)
    }

val bridgeTasks = mapOf(
    "debug" to registerGoBridge("debug", internalTrust = false),
    "internal" to registerGoBridge("internal", internalTrust = true),
    "release" to registerGoBridge("release", internalTrust = false),
)

tasks.configureEach {
    val lowerName = name.lowercase(Locale.ROOT)
    bridgeTasks.forEach { (buildType, bridgeTask) ->
        if (
            lowerName.contains(buildType) &&
            (lowerName.contains("configurecmake") || lowerName.contains("buildcmake") || lowerName.contains("pre${buildType}build"))
        ) {
            dependsOn(bridgeTask)
        }
    }
}

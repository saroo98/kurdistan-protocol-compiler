import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.Exec
import org.cyclonedx.Version
import org.cyclonedx.gradle.CyclonedxAggregateTask
import org.cyclonedx.gradle.CyclonedxDirectTask
import org.cyclonedx.model.Component
import java.security.MessageDigest
import java.util.Properties

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.cyclonedx)
}

val invokedFromAndroidStudio = providers.gradleProperty("android.injected.invoked.from.ide")
    .map(String::toBoolean)
    .orElse(false)

val releaseVersionProperties = Properties().apply {
    rootProject.file("../config/release/version.properties").inputStream().use(::load)
}
val releaseVersionName = requireNotNull(releaseVersionProperties.getProperty("versionName")) {
    "config/release/version.properties is missing versionName"
}
val releaseVersionCode = requireNotNull(releaseVersionProperties.getProperty("versionCode")) {
    "config/release/version.properties is missing versionCode"
}.toInt()
require(releaseVersionName.isNotBlank()) { "release versionName must not be blank" }
require(releaseVersionCode > 0) { "release versionCode must be positive" }
extra["releaseVersionName"] = releaseVersionName
extra["releaseVersionCode"] = releaseVersionCode

val configuredSdk = rootProject.file("local.properties").takeIf(File::isFile)?.let { propertiesFile ->
    Properties().run {
        propertiesFile.inputStream().use(::load)
        getProperty("sdk.dir")
    }
}
val androidSdkDirectory = file(
    configuredSdk
        ?: System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: error("Android SDK not found; configure sdk.dir, ANDROID_HOME, or ANDROID_SDK_ROOT"),
)
val adbExecutable = androidSdkDirectory.resolve(
    "platform-tools/${if (System.getProperty("os.name").startsWith("Windows")) "adb.exe" else "adb"}",
)

allprojects {
    group = "org.kurdistanvpn"
    version = releaseVersionName
    dependencyLocking {
        lockAllConfigurations()
        // Android Studio resolves ephemeral Configuration copies whose generated
        // names cannot have stable lockfile entries. Existing lock state remains
        // enforced in DEFAULT mode; CLI and CI retain STRICT completeness checks.
        lockMode.set(if (invokedFromAndroidStudio.get()) LockMode.DEFAULT else LockMode.STRICT)
    }
    tasks.withType<CyclonedxDirectTask>().configureEach {
        includeConfigs.set(listOf("releaseRuntimeClasspath"))
        skipConfigs.set(emptyList())
        includeMetadataResolution.set(true)
        includeBuildEnvironment.set(false)
        includeBomSerialNumber.set(false)
        includeBuildSystem.set(false)
        includeLicenseText.set(false)
        schemaVersion.set(Version.VERSION_16)
        projectType.set(Component.Type.LIBRARY)
    }
}

tasks.withType<CyclonedxAggregateTask>().configureEach {
    componentGroup.set("org.kurdistanvpn")
    componentName.set("KurdistanVPN")
    componentVersion.set(releaseVersionName)
    includeBomSerialNumber.set(false)
    includeBuildSystem.set(false)
    includeLicenseText.set(false)
    schemaVersion.set(Version.VERSION_16)
    projectType.set(Component.Type.APPLICATION)
}

fun sha256(path: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    path.inputStream().buffered().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

val phaseSnapshotRoot = providers.gradleProperty("phaseSnapshotRoot")
val phase16SnapshotHashes = mapOf(
    "app-release-unsigned.apk" to "2bd10c95aee3b61cf40b817cc4131cbdcdaf0bce7f7e13539e01d99925236cf6",
    "app-internal.apk" to "87a5cac5876038b58723625dc7deeac68160f11c96bd9009a738c2af226ecfc2",
    "AndroidManifest.xml" to "c8918a762d9e8ed3458b758ce19ca1634317cc58d041ca60edea72d9dbc84117",
)

fun registerSnapshotArtifactVerification(name: String, phaseFlag: String?) = tasks.register<Exec>(name) {
    group = "verification"
    description = "Manually reproduces the frozen Phase 16 predecessor artifact policy from an explicit ignored snapshot."
    workingDir(rootProject.projectDir.parentFile)
    doFirst {
        val snapshot = phaseSnapshotRoot.orNull?.takeIf(String::isNotBlank)
            ?: error("$name requires -PphaseSnapshotRoot=<ignored Phase 16 snapshot directory>")
        val root = file(snapshot).canonicalFile
        val artifacts = phase16SnapshotHashes.mapValues { (fileName, expected) ->
            val path = root.resolve(fileName)
            require(path.isFile) { "$name snapshot file is missing: $path" }
            val actual = sha256(path)
            require(actual == expected) { "$name snapshot digest mismatch for $fileName" }
            path
        }
        val arguments = mutableListOf("go", "run", "./cmd/phase9verify")
        if (phaseFlag != null) arguments += phaseFlag
        arguments += listOf(
            "-release-apk", artifacts.getValue("app-release-unsigned.apk").absolutePath,
            "-internal-apk", artifacts.getValue("app-internal.apk").absolutePath,
            "-manifest", artifacts.getValue("AndroidManifest.xml").absolutePath,
        )
        commandLine(arguments)
    }
}

val verifyPhase9SnapshotArtifacts = registerSnapshotArtifactVerification("verifyPhase9SnapshotArtifacts", null)
val verifyPhase10SnapshotArtifacts = registerSnapshotArtifactVerification("verifyPhase10SnapshotArtifacts", "-phase10")
val verifyPhase11SnapshotArtifacts = registerSnapshotArtifactVerification("verifyPhase11SnapshotArtifacts", "-phase11")

val verifyHistoricalAndroidMilestones = tasks.register<Exec>("verifyHistoricalAndroidMilestones") {
    group = "verification"
    description = "Verifies historical Phase 9 through Phase 14 source, evidence, mutation, and policy compatibility at predecessor 07c7fcfc."
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "test",
        "./cmd/phase9evidence",
        "./cmd/phase9verify",
        "./cmd/phase13verify",
        "./cmd/phase14verify",
        "-count=1",
    )
}

val verifyPhase13Artifacts = tasks.register<Exec>("verifyPhase13Artifacts") {
    group = "verification"
    description = "Verifies the historical Phase 13 source and verified-session boundary."
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/phase13verify", "-root", ".")
}

val verifyPhase14Artifacts = tasks.register<Exec>("verifyPhase14Artifacts") {
    group = "verification"
    description = "Validates the historical fail-closed Phase 14 assurance and release-readiness record."
    dependsOn(verifyPhase13Artifacts)
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/phase14verify", "-root", ".")
}

val verifyPhase17QualificationSource = tasks.register<Exec>("verifyPhase17QualificationSource") {
    group = "verification"
    description = "Runs the public, credential-free Phase 17 qualification policy, schema, privacy, wrapper, and boundary proof."
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/gate", "-proof", "phase17-qualification")
}

val verifyPhase17Artifacts = tasks.register<Exec>("verifyPhase17Artifacts") {
    group = "verification"
    description = "Inspects the current live Phase 17 Android APK, manifest, ABI, native symbols, privacy, and evidence boundary."
    dependsOn(":app:assembleRelease", ":app:assembleInternal")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase17verify",
        "-root",
        ".",
        "-release-apk",
        "android/app/build/outputs/apk/release/app-release-unsigned.apk",
        "-internal-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-manifest",
        "android/app/build/intermediates/merged_manifests/release/processReleaseManifest/AndroidManifest.xml",
    )
}

tasks.register("phase9Gate") {
    group = "verification"
    description = "Runs historical Phase 9 source/evidence compatibility for predecessor 07c7fcfc; it does not inspect the current APK."
    dependsOn(
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        verifyHistoricalAndroidMilestones,
    )
}

tasks.register("phase10Gate") {
    group = "verification"
    description = "Runs historical Phase 10 source/evidence compatibility for predecessor 07c7fcfc; it does not inspect the current APK."
    dependsOn(
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyHistoricalAndroidMilestones,
    )
}

tasks.register("phase11Gate") {
    group = "verification"
    description = "Runs historical Phase 11 source/evidence compatibility for predecessor 07c7fcfc; it does not inspect the current APK."
    dependsOn(
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyHistoricalAndroidMilestones,
    )
}

tasks.register("phase13Gate") {
    group = "verification"
    description = "Runs historical Phase 13 source/evidence compatibility for predecessor 07c7fcfc; it does not inspect the current APK."
    dependsOn(
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":core:model:testDebugUnitTest",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":data:settings:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyHistoricalAndroidMilestones,
        verifyPhase13Artifacts,
    )
}

val phase14Gate = tasks.register("phase14Gate") {
    group = "verification"
    description = "Runs historical Phase 14 source/evidence compatibility for predecessor 07c7fcfc; it does not inspect the current APK."
    dependsOn(
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":core:model:testDebugUnitTest",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":data:settings:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyHistoricalAndroidMilestones,
        verifyPhase14Artifacts,
    )
}

val phase17Gate = tasks.register("phase17Gate") {
    group = "verification"
    description = "Runs the cache-independent current Phase 17 live data-plane Android verification bar."
    dependsOn(
        ":app:assembleRelease",
        ":app:assembleInternal",
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":core:model:testDebugUnitTest",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":data:settings:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyPhase13Artifacts,
        verifyPhase14Artifacts,
        verifyPhase17QualificationSource,
        verifyPhase17Artifacts,
    )
}

tasks.register<Exec>("phase9DeviceGate") {
    group = "verification"
    description = "Runs Phase 9 on a connected device and rejects crashes or zero-test false passes."
    dependsOn(":app:assembleInternal", ":app:assembleInternalAndroidTest")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9devicegate",
        "-adb",
        adbExecutable.absolutePath,
        "-app-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-test-apk",
        "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk",
        "-app-package",
        "org.kurdistanvpn.app.internal",
        "-test-package",
        "org.kurdistanvpn.app.internal.test",
        "-conflicting-app-package",
        "org.kurdistanvpn.app.debug",
        "-minimum-tests",
        "5",
    )
}

tasks.register<Exec>("phase10DeviceGate") {
    group = "verification"
    description = "Runs the Phase 9 foundation and bounded Phase 10 VPN tests on a connected device."
    dependsOn(":app:assembleInternal", ":app:assembleInternalAndroidTest")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9devicegate",
        "-adb",
        adbExecutable.absolutePath,
        "-app-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-test-apk",
        "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk",
        "-app-package",
        "org.kurdistanvpn.app.internal",
        "-test-package",
        "org.kurdistanvpn.app.internal.test",
        "-conflicting-app-package",
        "org.kurdistanvpn.app.debug",
        "-minimum-tests",
        "8",
    )
}

tasks.register<Exec>("phase11DeviceGate") {
    group = "verification"
    description = "Runs all Android foundation, VPN, and Kurd loopback transport tests on a connected device."
    dependsOn(":app:assembleInternal", ":app:assembleInternalAndroidTest")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9devicegate",
        "-label",
        "PHASE 11",
        "-evidence-dir",
        ".tools/phase11/device-gate/latest",
        "-adb",
        adbExecutable.absolutePath,
        "-app-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-test-apk",
        "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk",
        "-app-package",
        "org.kurdistanvpn.app.internal",
        "-test-package",
        "org.kurdistanvpn.app.internal.test",
        "-conflicting-app-package",
        "org.kurdistanvpn.app.debug",
        "-minimum-tests",
        "19",
    )
}

tasks.register<Exec>("phase13DeviceGate") {
    group = "verification"
    description = "Runs the exact Phase 13 Android product test manifest on a connected device."
    dependsOn(":app:assembleInternal", ":app:assembleInternalAndroidTest")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9devicegate",
        "-label",
        "PHASE 13",
        "-evidence-dir",
        ".tools/phase13/device-gate/latest",
        "-adb",
        adbExecutable.absolutePath,
        "-app-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-test-apk",
        "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk",
        "-app-package",
        "org.kurdistanvpn.app.internal",
        "-test-package",
        "org.kurdistanvpn.app.internal.test",
        "-conflicting-app-package",
        "org.kurdistanvpn.app.debug",
        "-minimum-tests",
        "26",
        "-expected-tests",
        "android/config/phase13-required-device-tests.txt",
    )
}

tasks.register<Exec>("phase14DeviceGate") {
    group = "verification"
    description = "Runs the exact Phase 14 local assurance manifest on a connected device."
    dependsOn(":app:assembleInternal", ":app:assembleInternalAndroidTest")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9devicegate",
        "-label",
        "PHASE 14",
        "-evidence-dir",
        ".tools/phase14/device-gate/latest",
        "-adb",
        adbExecutable.absolutePath,
        "-app-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-test-apk",
        "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk",
        "-app-package",
        "org.kurdistanvpn.app.internal",
        "-test-package",
        "org.kurdistanvpn.app.internal.test",
        "-conflicting-app-package",
        "org.kurdistanvpn.app.debug",
        "-minimum-tests",
        "28",
        "-expected-tests",
        "android/config/phase14-required-device-tests.txt",
    )
}

tasks.register<Exec>("phase17DeviceGate") {
    group = "verification"
    description = "Runs the exact current Phase 17 device inventory on a connected API 26, 34, or 36 device."
    dependsOn(":app:assembleInternal", ":app:assembleInternalAndroidTest")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase17devicegate",
        "-adb",
        adbExecutable.absolutePath,
        "-app-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-test-apk",
        "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk",
        "-app-package",
        "org.kurdistanvpn.app.internal",
        "-test-package",
        "org.kurdistanvpn.app.internal.test",
        "-conflicting-app-package",
        "org.kurdistanvpn.app.debug",
        "-expected-tests",
        "android/config/phase17-required-device-tests.txt",
        "-minimum-tests",
        "1",
    )
}

val ciReleaseMetadata = tasks.register<Exec>("ciReleaseMetadata") {
    group = "verification"
    description = "Validates centralized release metadata in offline, non-authoritative mode."
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/releaseverify", "-root", ".")
}

tasks.register("ciPrHostGate") {
    group = "verification"
    description = "Runs the current Phase 17 host proof and centralized metadata check for pull requests."
    dependsOn(phase17Gate, ciReleaseMetadata)
}

tasks.register("ciAssuranceHostGate") {
    group = "verification"
    description = "Runs the current Phase 17 host proof and centralized metadata check for assurance."
    dependsOn(phase17Gate, ciReleaseMetadata)
}

tasks.register("ciDeviceArtifacts") {
    group = "build"
    description = "Builds one internal APK pair and writes deterministic, non-authoritative artifact metadata."
    dependsOn(":app:writeCiDeviceArtifactMetadata")
}

tasks.register("ciEngineeringCandidate") {
    group = "build"
    description = "Builds unsigned engineering artifacts and writes deterministic, non-authoritative metadata."
    dependsOn(":app:writeCiEngineeringCandidateMetadata")
}

import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.Exec
import org.cyclonedx.Version
import org.cyclonedx.gradle.CyclonedxAggregateTask
import org.cyclonedx.gradle.CyclonedxDirectTask
import org.cyclonedx.model.Component
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

val verifyPhase9Artifacts = tasks.register<Exec>("verifyPhase9Artifacts") {
    group = "verification"
    description = "Inspects the built release boundary, native symbols, and trust separation."
    dependsOn(":app:assembleRelease", ":app:assembleInternal")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9verify",
        "-release-apk",
        "android/app/build/outputs/apk/release/app-release-unsigned.apk",
        "-internal-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-manifest",
        "android/app/build/intermediates/merged_manifests/release/processReleaseManifest/AndroidManifest.xml",
    )
}

val verifyPhase10Artifacts = tasks.register<Exec>("verifyPhase10Artifacts") {
    group = "verification"
    description = "Inspects the bounded Phase 10 VPN runtime and release artifact boundary."
    dependsOn(":app:assembleRelease", ":app:assembleInternal")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9verify",
        "-phase10",
        "-release-apk",
        "android/app/build/outputs/apk/release/app-release-unsigned.apk",
        "-internal-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-manifest",
        "android/app/build/intermediates/merged_manifests/release/processReleaseManifest/AndroidManifest.xml",
    )
}

val verifyPhase11Artifacts = tasks.register<Exec>("verifyPhase11Artifacts") {
    group = "verification"
    description = "Inspects the bounded Phase 11 Kurd loopback transport and release trust boundary."
    dependsOn(":app:assembleRelease", ":app:assembleInternal")
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "go",
        "run",
        "./cmd/phase9verify",
        "-phase11",
        "-release-apk",
        "android/app/build/outputs/apk/release/app-release-unsigned.apk",
        "-internal-apk",
        "android/app/build/outputs/apk/internal/app-internal.apk",
        "-manifest",
        "android/app/build/intermediates/merged_manifests/release/processReleaseManifest/AndroidManifest.xml",
    )
}

val verifyPhase13Artifacts = tasks.register<Exec>("verifyPhase13Artifacts") {
    group = "verification"
    description = "Inspects the Phase 13 Android product artifact and verified-session boundary."
    dependsOn(verifyPhase11Artifacts)
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/phase13verify", "-root", ".")
}

val verifyPhase14Artifacts = tasks.register<Exec>("verifyPhase14Artifacts") {
    group = "verification"
    description = "Validates the fail-closed Phase 14 assurance and release-readiness record."
    dependsOn(verifyPhase13Artifacts)
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/phase14verify", "-root", ".")
}

val verifyPhase9Evidence = tasks.register<Exec>("verifyPhase9Evidence") {
    group = "verification"
    description = "Verifies canonical SBOM, SPDX license, and pinned toolchain evidence."
    dependsOn(":app:assembleRelease", "cyclonedxBom")
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/phase9evidence")
}

tasks.register("phase9Gate") {
    group = "verification"
    description = "Runs the cache-independent Phase 9 Android verification bar."
    dependsOn(
        ":app:assembleRelease",
        ":app:assembleInternal",
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        verifyPhase9Artifacts,
        verifyPhase9Evidence,
    )
}

tasks.register("phase10Gate") {
    group = "verification"
    description = "Runs the cache-independent bounded Phase 10 Android verification bar."
    dependsOn(
        ":app:assembleRelease",
        ":app:assembleInternal",
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyPhase10Artifacts,
    )
}

tasks.register("phase11Gate") {
    group = "verification"
    description = "Runs the cache-independent bounded Phase 11 Android verification bar."
    dependsOn(
        ":app:assembleRelease",
        ":app:assembleInternal",
        ":app:lintRelease",
        ":app:testInternalUnitTest",
        ":app:compileInternalAndroidTestKotlin",
        ":runtime:api:testDebugUnitTest",
        ":runtime:android:testDebugUnitTest",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        "cyclonedxBom",
        verifyPhase11Artifacts,
    )
}

tasks.register("phase13Gate") {
    group = "verification"
    description = "Runs the cache-independent Phase 13 Android product-completion verification bar."
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
    )
}

val phase14Gate = tasks.register("phase14Gate") {
    group = "verification"
    description = "Runs the cache-independent Phase 14 local assurance and release-readiness bar."
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
        verifyPhase14Artifacts,
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

val ciReleaseMetadata = tasks.register<Exec>("ciReleaseMetadata") {
    group = "verification"
    description = "Validates centralized release metadata in offline, non-authoritative mode."
    workingDir(rootProject.projectDir.parentFile)
    commandLine("go", "run", "./cmd/releaseverify", "-root", ".")
}

tasks.register("ciPrHostGate") {
    group = "verification"
    description = "Runs the existing Phase 14 host proof and centralized metadata check for pull requests."
    dependsOn(phase14Gate, ciReleaseMetadata)
}

tasks.register("ciAssuranceHostGate") {
    group = "verification"
    description = "Runs the existing Phase 14 host proof and centralized metadata check for assurance."
    dependsOn(phase14Gate, ciReleaseMetadata)
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

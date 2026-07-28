import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.Exec
import org.cyclonedx.Version
import org.cyclonedx.gradle.CyclonedxAggregateTask
import org.cyclonedx.gradle.CyclonedxDirectTask
import org.cyclonedx.model.Component

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.cyclonedx)
}

allprojects {
    group = "org.kurdistanvpn"
    version = "0.9.0"
    dependencyLocking {
        lockAllConfigurations()
        lockMode.set(LockMode.STRICT)
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
    componentVersion.set("0.9.0")
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
        ":app:testDebugUnitTest",
        ":app:compileDebugAndroidTestKotlin",
        ":data:metadata:testDebugUnitTest",
        ":data:secure:testDebugUnitTest",
        ":platform:import:testDebugUnitTest",
        verifyPhase9Artifacts,
        verifyPhase9Evidence,
    )
}

import com.android.build.api.artifact.SingleArtifact
import org.gradle.api.tasks.Exec

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

val releaseVersionName: String by rootProject.extra
val releaseVersionCode: Int by rootProject.extra

android {
    namespace = "org.kurdistanvpn.app"
    testBuildType = "internal"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.kurdistanvpn.app"
        minSdk = 26
        targetSdk = 36
        versionCode = releaseVersionCode
        versionName = releaseVersionName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables.useSupportLibrary = true
    }

    buildTypes {
        debug {
            ndk {
                abiFilters += setOf("arm64-v8a", "x86_64")
            }
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isPseudoLocalesEnabled = true
        }
        create("internal") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".internal"
            versionNameSuffix = "-internal"
            matchingFallbacks += listOf("debug")
            isPseudoLocalesEnabled = true
        }
        release {
            ndk {
                abiFilters.clear()
                abiFilters += "arm64-v8a"
            }
            isMinifyEnabled = true
            isShrinkResources = true
            vcsInfo.include = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                rootProject.file("config/proguard/phase9-rules.pro"),
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf(
            "META-INF/AL2.0",
            "META-INF/LGPL2.1",
        )
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

val repositoryDirectory = rootProject.projectDir.parentFile

androidComponents {
    onVariants(selector().withName("internal")) { variant ->
        val appApkDirectory = variant.artifacts.get(SingleArtifact.APK)
        val appApkLoader = variant.artifacts.getBuiltArtifactsLoader()
        val testComponent = requireNotNull(variant.androidTest) {
            "internal Android test component is required for CI device artifacts"
        }
        val testApkDirectory = testComponent.artifacts.get(SingleArtifact.APK)
        val testApkLoader = testComponent.artifacts.getBuiltArtifactsLoader()
        val expectedTests = rootProject.file("config/phase14-required-device-tests.txt")
        val metadataOutput = rootProject.layout.buildDirectory.file("ci/device-artifacts.json")

        tasks.register<Exec>("writeCiDeviceArtifactMetadata") {
            group = "build"
            description = "Builds and hashes the exact internal app and instrumentation APK pair."
            dependsOn("assembleInternal", "assembleInternalAndroidTest")
            inputs.dir(appApkDirectory)
            inputs.dir(testApkDirectory)
            inputs.file(expectedTests)
            outputs.file(metadataOutput)
            workingDir(repositoryDirectory)
            doFirst {
                val appArtifacts = requireNotNull(appApkLoader.load(appApkDirectory.get())) {
                    "internal APK metadata is missing"
                }
                val testArtifacts = requireNotNull(testApkLoader.load(testApkDirectory.get())) {
                    "internal instrumentation APK metadata is missing"
                }
                val appApk = appArtifacts.elements.singleOrNull()?.outputFile?.let(::file)
                    ?: error("require exactly one internal application APK")
                val testApk = testArtifacts.elements.singleOrNull()?.outputFile?.let(::file)
                    ?: error("require exactly one internal instrumentation APK")
                fun relative(path: File) = path.relativeTo(repositoryDirectory).invariantSeparatorsPath
                commandLine(
                    "go",
                    "run",
                    "./cmd/releaseverify",
                    "-root",
                    ".",
                    "-artifact-subject",
                    "DEVICE_TEST_SET",
                    "-artifact-metadata",
                    relative(metadataOutput.get().asFile),
                    "-artifact",
                    "internal-apk=${relative(appApk)}",
                    "-artifact",
                    "instrumentation-apk=${relative(testApk)}",
                    "-artifact",
                    "expected-tests=${relative(expectedTests)}",
                )
            }
        }
    }

    onVariants(selector().withName("release")) { variant ->
        val apkDirectory = variant.artifacts.get(SingleArtifact.APK)
        val apkLoader = variant.artifacts.getBuiltArtifactsLoader()
        val bundle = variant.artifacts.get(SingleArtifact.BUNDLE)
        val mapping = variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE)
        val mergedManifest = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)
        val nativeDebugSymbols = layout.buildDirectory.file(
            "outputs/native-debug-symbols/release/native-debug-symbols.zip",
        )
        val cyclonedx = rootProject.layout.buildDirectory.file("reports/cyclonedx/bom.json")
        val licenseEvidence = repositoryDirectory.resolve("testdata/evidence/phase9/android-licenses.spdx.json")
        val releaseProducts = repositoryDirectory.resolve("config/release/products.json")
        val releaseVersion = repositoryDirectory.resolve("config/release/version.properties")
        val metadataOutput = rootProject.layout.buildDirectory.file("ci/engineering-candidate.json")

        tasks.register<Exec>("writeCiEngineeringCandidateMetadata") {
            group = "build"
            description = "Builds and hashes unsigned engineering-candidate artifacts without signing or publication."
            dependsOn("assembleRelease", "bundleRelease", ":cyclonedxBom")
            inputs.dir(apkDirectory)
            inputs.file(bundle)
            inputs.file(mapping)
            inputs.file(mergedManifest)
            inputs.file(nativeDebugSymbols)
            inputs.file(cyclonedx)
            inputs.file(licenseEvidence)
            inputs.file(releaseProducts)
            inputs.file(releaseVersion)
            outputs.file(metadataOutput)
            workingDir(repositoryDirectory)
            doFirst {
                val apkArtifacts = requireNotNull(apkLoader.load(apkDirectory.get())) {
                    "release APK metadata is missing"
                }
                val releaseApk = apkArtifacts.elements.singleOrNull()?.outputFile?.let(::file)
                    ?: error("require exactly one release APK")
                fun relative(path: File) = path.relativeTo(repositoryDirectory).invariantSeparatorsPath
                commandLine(
                    "go",
                    "run",
                    "./cmd/releaseverify",
                    "-root",
                    ".",
                    "-artifact-subject",
                    "UNSIGNED_ENGINEERING_CANDIDATE",
                    "-artifact-metadata",
                    relative(metadataOutput.get().asFile),
                    "-artifact",
                    "unsigned-apk=${relative(releaseApk)}",
                    "-artifact",
                    "unsigned-aab=${relative(bundle.get().asFile)}",
                    "-artifact",
                    "mapping=${relative(mapping.get().asFile)}",
                    "-artifact",
                    "native-debug-symbols=${relative(nativeDebugSymbols.get().asFile)}",
                    "-artifact",
                    "cyclonedx-sbom=${relative(cyclonedx.get().asFile)}",
                    "-artifact",
                    "license-evidence=${relative(licenseEvidence)}",
                    "-artifact",
                    "merged-manifest=${relative(mergedManifest.get().asFile)}",
                    "-artifact",
                    "release-products=${relative(releaseProducts)}",
                    "-artifact",
                    "release-version=${relative(releaseVersion)}",
                )
            }
        }
    }
}

dependencies {
    implementation(project(":core:model"))
    implementation(project(":core:ui"))
    implementation(project(":domain"))
    implementation(project(":core:native-api"))
    implementation(project(":core:native-jni"))
    implementation(project(":data:metadata"))
    implementation(project(":data:secure"))
    implementation(project(":data:settings"))
    implementation(project(":platform:import"))
    implementation(project(":runtime:api"))
    implementation(project(":runtime:android"))
    implementation(project(":feature:home"))
    implementation(project(":feature:profiles"))
    implementation(project(":feature:settings-recovery"))
    implementation(project(":feature:diagnostics-about"))
    "internalImplementation"(project(":test:fixtures"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.compose.runtime)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.navigation3.runtime)
    implementation(libs.androidx.navigation3.ui)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.coroutines.android)

    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    "internalImplementation"(libs.androidx.compose.ui.test.manifest)
    testImplementation(libs.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4.accessibility)
}

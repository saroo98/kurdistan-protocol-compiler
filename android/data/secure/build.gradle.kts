plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.kurdistanvpn.data.secure"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { unitTests.isIncludeAndroidResources = true }
}

dependencies {
    implementation(project(":core:model"))
    implementation(project(":core:native-api"))
    implementation(project(":data:metadata"))
    implementation(libs.androidx.biometric)
    // Biometric 1.1.0 declares a 2020 Fragment version. Pin the current stable
    // Fragment runtime so its FragmentActivity interoperates with Activity 1.12.
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.room.ktx)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit4)
}

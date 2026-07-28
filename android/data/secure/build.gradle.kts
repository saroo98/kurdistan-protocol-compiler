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
    implementation(libs.androidx.room.ktx)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit4)
}

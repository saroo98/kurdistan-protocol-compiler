plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.kurdistanvpn.platform.system"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":core:model"))
    implementation(project(":domain"))
    implementation(project(":runtime:api"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.window)
    testImplementation(libs.androidx.window.testing)
    testImplementation(libs.junit4)
}

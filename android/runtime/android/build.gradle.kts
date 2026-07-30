plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.kurdistanvpn.runtime.android"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":runtime:api"))
    implementation(project(":core:native-api"))
    implementation(project(":core:native-jni"))
    testImplementation(libs.junit4)
}

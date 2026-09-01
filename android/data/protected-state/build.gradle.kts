plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.kurdistanvpn.data.protectedstate"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    buildTypes {
        create("internal") { initWith(getByName("debug")); matchingFallbacks += listOf("debug") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { unitTests.isIncludeAndroidResources = true }
}

dependencies {
    implementation(project(":core:model"))
    implementation(project(":core:native-api"))
    implementation(project(":core:native-jni"))
    implementation(project(":data:metadata"))
    implementation(project(":data:secure"))
    implementation(project(":data:settings"))
    implementation(project(":runtime:api"))
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit4)
}

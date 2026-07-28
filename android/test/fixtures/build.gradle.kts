plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.kurdistanvpn.test.fixtures"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":core:model"))
}

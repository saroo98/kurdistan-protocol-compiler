android {
    defaultConfig {
        applicationId = "org.kurdistanvpn.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.9.0"
    }

    buildTypes {
        create("internal") {
            applicationIdSuffix = ".internal"
        }
        release {
            ndk {
                abiFilters += "arm64-v8a"
            }
        }
    }
}

val releaseVersionName: String by rootProject.extra
val releaseVersionCode: Int by rootProject.extra

android {
    defaultConfig {
        applicationId = "org.kurdistanvpn.app"
        minSdk = 26
        targetSdk = 36
        versionCode = releaseVersionCode
        versionName = releaseVersionName
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

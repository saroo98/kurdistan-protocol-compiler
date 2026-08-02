val releaseVersionProperties = Properties().apply {
    rootProject.file("../config/release/version.properties").inputStream().use(::load)
}
val releaseVersionName = requireNotNull(releaseVersionProperties.getProperty("versionName"))
val releaseVersionCode = requireNotNull(releaseVersionProperties.getProperty("versionCode")).toInt()
extra["releaseVersionName"] = releaseVersionName
extra["releaseVersionCode"] = releaseVersionCode

allprojects {
    version = releaseVersionName
}

componentVersion.set(releaseVersionName)

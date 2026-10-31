plugins {
    id("com.android.application")
}

android {
    namespace = "df.vivo.probe"
    compileSdk = 34

    defaultConfig {
        applicationId = "df.vivo.probe"
        minSdk = 24
        // targetSdk 27 is deliberate: it places the app in the legacy
        // untrusted_app_27 SELinux domain, which still has read access to
        // /proc/net (needed for the xfrm_stat diagnostics the probe reports).
        // Any targetSdk >= 28 domain cannot read /proc/net on Android 9+.
        targetSdk = 27
        versionCode = 1
        versionName = "0.1-probe"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

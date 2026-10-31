plugins {
    id("com.android.application")
}

android {
    namespace = "df.vivo.probe"
    compileSdk = 34
    // Google removed 26.1.10909165 (AGP 8.5's default) from the SDK repo;
    // pin the r26.1 revision that is still listed (26.1.10909125).
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "df.vivo.probe"
        minSdk = 24
        // targetSdk 27 is deliberate: legacy untrusted_app_27 SELinux domain
        // keeps /proc/net readable for the xfrm_stat diagnostics.
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

    // Force extraction of native libs into nativeLibraryDir so the app can
    // execve the probe binary (same as DFRoot). Without this, AGP stores the
    // .so unextracted, nativeLibraryDir stays empty, and execve fails with
    // "error=2, No such file or directory".
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

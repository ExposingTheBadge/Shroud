plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// One version for every client: the repo's VERSION file. This used to be
// hard-coded and had drifted to 2.4.5 while the project shipped 2.6.x.
val shroudVersion: String = rootProject.file("../../VERSION").readText().trim()
val shroudVersionCode: Int = shroudVersion.split(".").map { it.toInt() }
    .let { (major, minor, patch) -> major * 10000 + minor * 100 + patch }

android {
    namespace = "com.shroud.client"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.shroud.client"
        minSdk = 26
        targetSdk = 34
        versionCode = shroudVersionCode   // 2.6.7 -> 20607, always above the old 19
        versionName = shroudVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            storeFile = file("shroud.keystore")
            storePassword = System.getenv("SHROUD_KEYSTORE_PASS") ?: "changeit"
            keyAlias = "shroud"
            keyPassword = System.getenv("SHROUD_KEY_PASS") ?: "changeit"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            // Use the default Android debug keystore so emulator + local
            // testing works out of the box. Release signing is gated
            // behind SHROUD_KEYSTORE_PASS so it still uses the real key.
            isDebuggable = true
        }
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // JVM unit tests. AnonRouting is pure java.security/javax.crypto,
    // so its wire-format vectors can be pinned without a device.
    testImplementation("junit:junit:4.13.2")
    implementation(platform("androidx.compose:compose-bom:2024.01.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.lifecycle:lifecycle-process:2.7.0")           // ProcessLifecycleOwner for PIN auto-lock
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("org.json:json:20231013")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

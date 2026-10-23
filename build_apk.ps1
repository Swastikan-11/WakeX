# WakeX APK Build Script (Java 21 + Android SDK Build-Tools 35)
$ErrorActionPreference = "Stop"

$sdkPath = if ($env:ANDROID_HOME -and (Test-Path $env:ANDROID_HOME)) {
    $env:ANDROID_HOME
} else {
    Join-Path $env:LOCALAPPDATA "Android\Sdk"
}
$buildTools33 = "$sdkPath\build-tools\33.0.1"
$buildTools35 = "$sdkPath\build-tools\35.0.0"
$androidJar = "$sdkPath\platforms\android-33\android.jar"
$baseDir = Join-Path $PSScriptRoot "android_build"
$outputDir = "$baseDir\bin"
$finalApk = Join-Path $PSScriptRoot "WakeX.apk"
$staticApk = Join-Path $PSScriptRoot "static\wakex.apk"

Write-Host ">>> [1/6] Cleaning build directory..."
if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }
New-Item -ItemType Directory -Path "$outputDir\classes" -Force | Out-Null

Write-Host ">>> [2/6] Generating R.java with aapt..."
& "$buildTools33\aapt.exe" package -f -m -J "$baseDir\src" -M "$baseDir\AndroidManifest.xml" -S "$baseDir\res" -I $androidJar

Write-Host ">>> [3/6] Compiling Java classes with javac..."
$javaFiles = Get-ChildItem -Path "$baseDir\src" -Filter "*.java" -Recurse | Select-Object -ExpandProperty FullName
& "javac" -source 8 -target 8 -cp $androidJar -d "$outputDir\classes" $javaFiles

Write-Host ">>> [4/6] Dexing bytecode with D8 (Java 21 compatible)..."
$classFiles = Get-ChildItem -Path "$outputDir\classes" -Filter "*.class" -Recurse | Select-Object -ExpandProperty FullName
& "java" -cp "$buildTools35\lib\d8.jar" com.android.tools.r8.D8 --output $outputDir --lib $androidJar $classFiles

if (-not (Test-Path "$outputDir\classes.dex")) {
    throw "D8 failed to produce classes.dex"
}

Write-Host ">>> [5/6] Packaging and aligning APK..."
& "$buildTools33\aapt.exe" package -f -M "$baseDir\AndroidManifest.xml" -S "$baseDir\res" -I $androidJar -F "$outputDir\unaligned.apk"
# Add classes.dex into unaligned apk
Push-Location $outputDir
& "$buildTools33\aapt.exe" add "unaligned.apk" "classes.dex"
Pop-Location

# Zipalign
& "$buildTools33\zipalign.exe" -f -p 4 "$outputDir\unaligned.apk" "$outputDir\aligned.apk"

Write-Host ">>> [6/6] Signing APK with apksigner (External Release Keystore)..."
$ksDir = Join-Path $env:USERPROFILE ".wakex"
if (-not (Test-Path $ksDir)) {
    New-Item -ItemType Directory -Path $ksDir -Force | Out-Null
}
$keystore = if ($env:WAKEX_KEYSTORE_PATH) { $env:WAKEX_KEYSTORE_PATH } else { Join-Path $ksDir "wakex_release.keystore" }
$ksPass = if ($env:WAKEX_KEYSTORE_PASS) { $env:WAKEX_KEYSTORE_PASS } else { "WakeXRelease2026SecureKey" }
$ksAlias = if ($env:WAKEX_KEYSTORE_ALIAS) { $env:WAKEX_KEYSTORE_ALIAS } else { "wakex_release" }

if (-not (Test-Path $keystore)) {
    Write-Host "Generating fresh release keystore outside repository at: $keystore"
    & "keytool" -genkeypair -v -keystore $keystore -alias $ksAlias -keyalg RSA -keysize 2048 -validity 10000 -storepass $ksPass -keypass $ksPass -dname "CN=WakeX Release, O=WakeX Local, C=US"
}

& "java" -jar "$buildTools35\lib\apksigner.jar" sign --ks $keystore --ks-key-alias $ksAlias --ks-pass "pass:$ksPass" --key-pass "pass:$ksPass" --out $finalApk "$outputDir\aligned.apk"
Copy-Item -Path $finalApk -Destination $staticApk -Force

# Verify signature
Write-Host ">>> Verifying APK signature..."
& "java" -jar "$buildTools35\lib\apksigner.jar" verify $finalApk

$size = (Get-Item $finalApk).Length / 1KB
Write-Host ">>> [SUCCESS] WakeX.apk built and verified successfully! Size: $($size.ToString('F1')) KB" -ForegroundColor Green
Write-Host "Location: $finalApk"
Write-Host "Static web download updated: $staticApk"

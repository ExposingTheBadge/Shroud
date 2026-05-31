# Release archive

Every published SHROUD build is preserved here under `vX.Y.Z/`. This makes
it easy to:
- Diff binaries across versions
- Reinstall a specific older release without hitting GitHub
- Verify reproducible builds (hash the version-specific binary against the
  signed release manifest from `release/sign_manifest.py`)

## Layout

```
releases/
  v1.0.0/  SHROUD_v1.0.0.zip
  v1.1.0/  (TODO: rebuild from tag)
  v1.2.0/  (TODO)
  v1.3.0/  SHROUD-v1.3.0-win64.zip  (mirrored from GitHub release)
  v1.4.0/  (TODO)
  v1.5.0/  (TODO)
  v1.6.0/  (TODO)
  v1.7.0/  current
```

## Build flow per version

1. Tag the release: `git tag vX.Y.Z && git push origin vX.Y.Z`
2. Build the Windows EXE:
   ```
   cd clients/windows
   cmake -B build -G "Visual Studio 17 2022" -A x64
   cmake --build build --config Release
   ```
3. Build the Android APK:
   ```
   cd clients/android
   ./gradlew.bat assembleRelease
   ```
4. Copy the artifacts into `releases/vX.Y.Z/`:
   - `SHROUD-vX.Y.Z-win64.exe` (or .zip if bundling Qt DLLs)
   - `SHROUD-vX.Y.Z.apk`
5. Sign the manifest: `python release/sign_manifest.py --version X.Y.Z ...`
6. Attach to GitHub release: `gh release create vX.Y.Z releases/vX.Y.Z/*`

## What's missing today

Versions 1.1.0 through 1.6.0 do not have archived binaries because the
CI/build automation that produces them is not yet wired up. Each tagged
commit is buildable; only the artifacts are missing. See the build flow
above to backfill any version.

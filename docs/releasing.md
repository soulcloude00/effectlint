# Releasing

1. Confirm CI is green and `npm audit --audit-level=high` passes in `action/`.
2. Update versions and `CHANGELOG.md`.
3. Tag `vX.Y.Z`; the release workflow builds the Rust binaries and uploads checksums.
4. Build and commit the Action `dist/` bundle before moving the immutable release tag.
5. Move only the floating major tag (for example `v1`) after verifying the immutable tag.

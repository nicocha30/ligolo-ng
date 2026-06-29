#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  build/verify-release.sh <artifact-dir> <version> [owner/repo]

Example:
  gh release download v0.8.3-relay.1 --dir /tmp/ligolo-release
  build/verify-release.sh /tmp/ligolo-release v0.8.3-relay.1 allsmog/ligolo-ng-relay

Environment overrides:
  COSIGN_IDENTITY  Expected GitHub Actions OIDC certificate identity
  COSIGN_ISSUER    Expected OIDC issuer
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

release_dir="${1:-}"
version="${2:-}"
owner_repo="${3:-${GITHUB_REPOSITORY:-allsmog/ligolo-ng-relay}}"

if [ -z "$release_dir" ] || [ -z "$version" ]; then
  usage
  exit 2
fi

if [ ! -d "$release_dir" ]; then
  echo "release artifact directory not found: $release_dir" >&2
  exit 1
fi

checksums="$release_dir/checksums.txt"
bundle="$release_dir/checksums.txt.sigstore.json"
if [ ! -f "$checksums" ]; then
  echo "missing checksums file: $checksums" >&2
  exit 1
fi
if [ ! -f "$bundle" ]; then
  echo "missing Sigstore bundle: $bundle" >&2
  exit 1
fi

owner="${owner_repo%%/*}"
image_version="${version#v}"
identity="${COSIGN_IDENTITY:-https://github.com/${owner_repo}/.github/workflows/release.yml@refs/tags/${version}}"
issuer="${COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$release_dir" && sha256sum -c checksums.txt)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$release_dir" && shasum -a 256 -c checksums.txt)
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to verify Sigstore bundles and images" >&2
  exit 1
fi

cosign verify-blob \
  --bundle "$bundle" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$checksums"

images=(
  "ghcr.io/${owner}/ligolo-ng-relay-proxy:${image_version}"
  "ghcr.io/${owner}/ligolo-ng-relay-agent:${image_version}"
  "ghcr.io/${owner}/ligolo-ng-relayctl:${image_version}"
)

for image in "${images[@]}"; do
  cosign verify \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "$image"
done

echo "release artifacts and images verified for ${owner_repo}@${version}"

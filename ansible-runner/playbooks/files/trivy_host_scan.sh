#!/bin/sh
# Trivy scan of one Docker host, as a client of the Trivy server on .8 (which holds the vulnerability DB).
#   - every image a running container uses              -> img__<name>.json   (vulnerabilities)
#   - every git checkout under /home, /opt, /srv        -> git__<path>.json   (vulns + secrets + misconfig)
#   - TRIVY_GITHUB_REPOS (space-separated clone URLs)   -> gh__<repo>.json    (vulns + secrets + misconfig)
# Env: TRIVY_SERVER, TRIVY_TOKEN, TRIVY_IMAGE, optional TRIVY_GITHUB_REPOS / GITHUB_TOKEN.
# Writes /tmp/trivy-results.tar.gz (JSON files + index.tsv: kind, target, file, status).
set -u
OUT=$(mktemp -d /tmp/trivy-results.XXXXXX)
CACHE=/var/cache/trivy-client; mkdir -p "$CACHE"
ENVF=$(mktemp); chmod 600 "$ENVF"
trap 'rm -rf "$OUT" "$ENVF"' EXIT
{ echo "TRIVY_TOKEN=$TRIVY_TOKEN"; [ -n "${GITHUB_TOKEN:-}" ] && echo "GITHUB_TOKEN=$GITHUB_TOKEN"; } > "$ENVF"

trivy() {  # trivy <out-file> <docker-run-args...> -- <trivy-args...>
  f=$1; shift; dargs=""
  while [ "$1" != "--" ]; do dargs="$dargs $1"; shift; done; shift
  # shellcheck disable=SC2086
  # --cpus 1: the hosts' disks sit on the NAS (iSCSI) - keep the scan from starving the apps
  timeout 1800 docker run --rm --cpus 1 --env-file "$ENVF" -v "$CACHE:/root/.cache/trivy" $dargs "$TRIVY_IMAGE" \
    "$@" --server "$TRIVY_SERVER" --token-header Trivy-Token --format json --quiet --timeout 25m \
    > "$OUT/$f" 2> "$OUT/$f.err"
}
safe() { echo "$1" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-150; }
record() {  # kind target file rc
  if [ "$4" -eq 0 ] && [ -s "$OUT/$3" ]; then printf '%s\t%s\t%s\tok\n' "$1" "$2" "$3"
  else printf '%s\t%s\t%s\tfailed: %s\n' "$1" "$2" "$3" "$(tail -c 300 "$OUT/$3.err" | tr '\t\n' '  ')"; rm -f "$OUT/$3"; fi >> "$OUT/index.tsv"
  rm -f "$OUT/$3.err"
}
: > "$OUT/index.tsv"

for img in $(docker ps --format '{{.Image}}' | sort -u); do
  f="img__$(safe "$img").json"
  # remote first: layers stream from the registry (no `docker save` of the whole image to the slow disk)
  # and layers already analysed are skipped via the cache; docker only for locally built images
  trivy "$f" -v /var/run/docker.sock:/var/run/docker.sock -- image --scanners vuln --image-src remote,docker "$img"; record image "$img" "$f" $?
done

for d in $(find /home /opt /srv -maxdepth 5 -name .git -type d -not -path '*/node_modules/*' 2>/dev/null | sed 's#/\.git$##' | sort); do
  f="git__$(safe "$d").json"
  trivy "$f" -v "$d:/src:ro" -- fs --scanners vuln,secret,misconfig /src; record checkout "$d" "$f" $?
done

for url in ${TRIVY_GITHUB_REPOS:-}; do
  f="gh__$(safe "$(basename "$url" .git)").json"
  trivy "$f" -- repo --scanners vuln,secret,misconfig "$url"; record github "$url" "$f" $?
done

tar -czf /tmp/trivy-results.tar.gz -C "$OUT" .
echo "scanned: $(grep -c "	ok$" "$OUT/index.tsv") ok, $(grep -c "	failed" "$OUT/index.tsv") failed"

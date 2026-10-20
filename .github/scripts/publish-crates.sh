#!/usr/bin/env bash
set -euo pipefail

# Publish order matters: a crate can only be published after the workspace
# crates it depends on are available on crates.io.
crates=(
  libverify-core
  libverify-policy
  libverify-vanta
  libverify-drata
  libverify-output
  libverify-github
  libverify-gitlab
)

# libverify-verif depends on a git checkout of Creusot, so it is not published.
excluded=(libverify-verif)

metadata="$(cargo metadata --no-deps --format-version 1)"

workspace_crates="$(
  jq -r '.packages[] | select(.publish != []) | .name' <<<"$metadata" | sort
)"
expected_crates="$(
  printf '%s\n' "${crates[@]}" "${excluded[@]}" | sort
)"
missing="$(comm -23 <(printf '%s\n' "$workspace_crates") <(printf '%s\n' "$expected_crates"))"
if [[ -n "$missing" ]]; then
  printf '::error::Publishable workspace crates are missing from this script: %s\n' "$missing" >&2
  exit 1
fi

declare -A versions=()
while IFS=$'\t' read -r name version; do
  versions["$name"]="$version"
done < <(jq -r '.packages[] | [.name, .version] | @tsv' <<<"$metadata")

crate_version_exists() {
  local crate="$1"
  local version="$2"
  local status
  status="$(
    curl --silent --show-error --location \
      --header 'User-Agent: libverify-publish-workflow' \
      --output /dev/null --write-out '%{http_code}' \
      "https://crates.io/api/v1/crates/${crate}/${version}"
  )"
  case "$status" in
    200) return 0 ;;
    404) return 1 ;;
    *)
      printf '::error::crates.io returned HTTP %s while checking %s %s\n' \
        "$status" "$crate" "$version" >&2
      exit 1
      ;;
  esac
}

published=()
pending=()
for crate in "${crates[@]}"; do
  version="${versions[$crate]}"
  if crate_version_exists "$crate" "$version"; then
    published+=("$crate")
  else
    pending+=("$crate")
  fi
done

if ((${#published[@]})); then
  printf 'Already published: %s\n' "${published[*]}"
fi
if ((${#pending[@]} == 0)); then
  echo 'All crates are already published for this version.'
  exit 0
fi

for i in "${!pending[@]}"; do
  crate="${pending[$i]}"
  version="${versions[$crate]}"
  echo "::group::Publish ${crate} ${version}"
  cargo publish --package "$crate"
  echo '::endgroup::'
  if ((i + 1 < ${#pending[@]})); then
    echo 'Waiting for the crates.io index to update...'
    sleep 30
  fi
done

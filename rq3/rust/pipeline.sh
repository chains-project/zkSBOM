#!/bin/bash

## CLI
TOTAL="$1"
PAGE_SIZE="$2"
METRIC="$3"

if [[ -z ${TOTAL} || -z ${PAGE_SIZE} || -z ${METRIC} ]]; then
	echo 'USAGE:   ./pipeline.sh <TOTAL> <PAGE_SIZE> <METRIC>'
	echo 'EXAMPLE: ./pipeline.sh 500 100 docker_downloads_count'
	echo ''
	echo ''
	echo '- TOTAL = n * PAGE_SIZE'
	echo '- METRIC in ["downloads", "dependent_repos_count", "docker_dependents_count", "docker_downloads_count"]'
	exit 0
fi


## Main
echo "Evaluating dependency metrics of top ${TOTAL} Rust (crates.io) crates, based on the metric '${METRIC}'"
echo "Using page size ${PAGE_SIZE}"

echo ''
echo '== COLLECTING PACKAGE NAMES =='
packages=''
pages=$(( (TOTAL + PAGE_SIZE - 1) / PAGE_SIZE ))
for ((page=1; page<=pages; page++)); do
	echo "Fetching page ${page} ..."

	url="https://packages.ecosyste.ms/api/v1/registries/crates.io/package_names?page=${page}&per_page=${PAGE_SIZE}&sort=${METRIC}"
	tmp=""; ok=0
	for ((attempt=1; attempt<=3; attempt++)); do
		response=$(curl -sX 'GET' "${url}" -H 'accept: application/json')
		if tmp=$(echo "${response}" | jq -er 'if type=="array" then .[] else error("not an array") end' 2>/dev/null); then
			ok=1; break
		fi
		echo "  ! jq parse error (attempt ${attempt}/3) on: ${url}"
		echo "  ! response: ${response}" | head -c 200
		[[ ${attempt} -lt 3 ]] && sleep 2
	done
	if [[ ${ok} -eq 0 ]]; then
		echo "  ! giving up on page ${page}"
		continue
	fi
	packages="${packages}${tmp}
"
done

echo ''
echo '== DETERMINING TRANSITIVE COUNT =='
counts=''
while IFS= read -r package; do
	rm -rf tmp/
	mkdir tmp/
	cd tmp/

  echo "Evaluating '${package}' ..."
	cargo init >/dev/null 2>&1
	cargo_stderr=$(mktemp)
	if ! timeout 30s cargo add "${package}" >/dev/null 2>"${cargo_stderr}"; then
		echo "  ! crate not resolved: $(grep -m1 'error\|warning\|timed out' "${cargo_stderr}" || head -1 "${cargo_stderr}")"
		rm -f "${cargo_stderr}"
		cd ..
		continue
	fi
	rm -f "${cargo_stderr}"

	tmp=$(cargo tree 2>/dev/null)

	version=$(echo "$tmp" | awk 'NR == 2' | awk '{print $3}')
	if [[ -z "${version}" ]]; then
		echo '  ! crate not found'
		cd ..
		continue
	fi

	transitive_count=$(echo "${tmp}" | grep -E '^ ' | wc -l)
	if [[ -z "${transitive_count}" ]]; then
		echo '  ! dependency count could not be determined'
		echo ''
		echo '=== DEBUG START ==='
		echo "${tmp}"
		echo '===  DEBUG END  ==='
		cd ..
		continue
	fi

	echo "  got ${version}"
	echo "  has ${transitive_count} dependencies"

	counts="${counts}${transitive_count}
"

	cd ..
done <<<"${packages}"

echo ''
echo '== COMPUTING STATS =='
sum=0
count=0
while IFS= read -r n; do
	echo "$n"
  sum=$((sum + n))
  count=$((count + 1))
done <<<"$(printf "%s\n" "$counts" | awk 'NF')"

echo ''
echo '== RESULTS =='
echo "avg # deps : $(echo "scale=2; ${sum} / ${count}" | bc) (=${sum}/${count})"

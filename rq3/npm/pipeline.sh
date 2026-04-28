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
echo "Evaluating dependency metrics of top ${TOTAL} npm packages, based on the metric '${METRIC}'"
echo "Using page size ${PAGE_SIZE}"

echo ''
echo '== COLLECTING PACKAGE NAMES =='
packages=''
pages=$(( (TOTAL + PAGE_SIZE - 1) / PAGE_SIZE ))
for ((page=1; page<=pages; page++)); do
	echo "Fetching page ${page} ..."

	url="https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names?page=${page}&per_page=${PAGE_SIZE}&sort=${METRIC}"
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
echo '== DETERMINING RELATIONS =='
counts_transitive=''
counts_peer=''
while IFS= read -r package; do
	rm -rf tmp/
	mkdir tmp/
	cd tmp/

  echo "Evaluating '${package}' ..."
	npm init -y >/dev/null 2>&1
	if ! timeout 30s npm install "${package}" --ignore-scripts=false --allow-git=none --audit=false --save-exact >/dev/null 2>&1; then
		echo '  ! package not resolved'
		cd ..
		continue
	fi

	tmp=$(npm ls --all 2>/dev/null)

	version=$(echo "$tmp" | awk 'NR == 2' | awk -F'@' '{print $2}')
	if [[ -z "${version}" ]]; then
		echo '  ! package not found'
		cd ..
		continue
	fi

	transitive_count=$(echo "${tmp}" | grep -E '^ ' | grep -vE 'deduped$' | grep -v ' UNMET ' | wc -l)
	if [[ -z "${transitive_count}" ]]; then
		echo '  ! dependency count could not be determined'
		echo ''
		echo '=== DEBUG START ==='
		echo "${tmp}"
		echo '===  DEBUG END  ==='
		cd ..
		continue
	fi

	peer_count=$(cat "node_modules/${package}/package.json" | jq '.peerDependencies // {} | keys | length')

	echo "  got ${version}"
	echo "  has ${transitive_count} dependencies"
	echo "  has ${peer_count} peers"

	counts_transitive="${counts_transitive}${transitive_count}
"
	counts_peer="${counts_peer}${peer_count}
"

	cd ..
done <<<"${packages}"

echo ''
echo '== COMPUTING STATS =='
transitive_count=0
transitive_sum=0
while IFS= read -r n; do
	echo "tran: $n"
  transitive_count=$((transitive_count + 1))
  transitive_sum=$((transitive_sum + n))
done <<<"$(printf "%s\n" "$counts_transitive" | awk 'NF')"

peer_count=0
peer_sum=0
while IFS= read -r n; do
	echo "peer: $n"
  peer_count=$((peer_count + 1))
  peer_sum=$((peer_sum + n))
done <<<"$(printf "%s\n" "$counts_peer" | awk 'NF')"

echo ''
echo '== RESULTS =='
echo "avg # deps : $(echo "scale=2; ${transitive_sum} / ${transitive_count}" | bc) (=${transitive_sum}/${transitive_count})"
echo "avg # peers: $(echo "scale=2; ${peer_sum} / ${peer_count}" | bc) (=${peer_sum}/${peer_count})"

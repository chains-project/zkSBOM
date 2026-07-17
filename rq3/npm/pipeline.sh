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
MAX_TRIES=100
packages=''
pages=$(( (TOTAL + PAGE_SIZE - 1) / PAGE_SIZE ))
for ((page=1; page<=pages; page++)); do
	echo "  Fetching page ${page} ..."

	url="https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names?page=${page}&per_page=${PAGE_SIZE}&sort=${METRIC}"
	tmp=""; ok=0; max=$MAX_TRIES
	for ((attempt=1; attempt<=max; attempt++)); do
		response=$(curl -sX 'GET' "${url}" -H 'accept: application/json')
		if tmp=$(echo "${response}" | jq -er 'if type=="array" then .[] else error("not an array") end' 2>/dev/null); then
			ok=1; break
		fi
		echo "    ! jq parse error (attempt ${attempt}/${max}) on: ${url}"
		echo '    === DEBUG START ==='       1>&2
		echo "${response}" | sed 's/^/    /' 1>&2
		echo '    ===  DEBUG END  ==='       1>&2
		timeout=2
		[[ ${attempt} -lt ${max} ]] && echo "    Sleeping for ${timeout}s" && sleep "${timeout}"
	done
	if [[ ${ok} -eq 0 ]]; then
		echo "    ! giving up on page ${page}"
		continue
	fi
	packages="${packages}${tmp}
"
done
packages="$(printf "%s" "${packages}")"

echo "DEB retrieved $(echo "${packages}" | wc -l) packages from the API"
echo "DEB of which  $(echo "${packages}" | sort | uniq | wc -l) are unique"

echo '*** start obtained list of packages ***'
echo "${packages}" | sed 's/^/  /'
echo '***  end  obtained list of packages ***'

packages=$(echo "${packages}" | sort)
packages="$(printf "%s" "${packages}")"
echo '*** start sorted list of packages ***'
echo "${packages}" | sed 's/^/  /'
echo '***  end  sorted list of packages ***'

packages=$(echo "${packages}" | uniq)
packages="$(printf "%s" "${packages}")"
echo '*** start deduplicated packages ***'
echo "${packages}" | sed 's/^/  /'
echo '***  end  deduplicated packages ***'

echo ''
echo '== DETERMINING RELATIONS =='
counts_transitive=''
counts_peer=''
considered_packages=''
while IFS= read -r package; do
	echo '  DEB rm -rf ~/.npm/'
	rm -rf ~/.npm/
	echo '  DEB rm -rf tmp/'
	rm -rf tmp/
	echo '  DEB mkdir tmp/'
	mkdir tmp/
	echo '  DEB cd tmp/'
	cd tmp/
	echo "  DEB pwd: $(pwd)"

	echo "  Evaluating '${package}' ..."
	npm init -y </dev/null >/dev/null 2>&1
	if ! timeout 300s npm install "${package}" --ignore-scripts=true --allow-git=none --audit=false --save-exact </dev/null >/dev/null 2>&1; then
		echo '    ! package not resolved'
		echo '    DEB cd ..'
		cd ..
		echo "    DEB pwd: $(pwd)"
		echo '    DEB continue'
		continue
	fi

	tmp=$(npm ls --all </dev/null 2>/dev/null)

	version=$(echo "$tmp" | awk 'NR == 2' | sed 's/.*@//')
	if [[ -z "${version}" ]]; then
		echo '    ! package not found'
		echo '    DEB cd ..'
		cd ..
		echo "    DEB pwd: $(pwd)"
		echo '    DEB continue'
		continue
	fi

	transitive_count=$(echo "${tmp}" | grep -E '^ ' | grep -vE 'deduped$' | grep -v ' UNMET ' | wc -l)
	if [[ -z "${transitive_count}" ]]; then
		echo '    ! dependency count could not be determined'
		echo '    === DEBUG START ==='  1>&2
		echo "${tmp}" | sed 's/^/    /' 1>&2
		echo '    ===  DEBUG END  ==='  1>&2
		cd ..
		continue
	fi

	peer_count=$(cat "node_modules/${package}/package.json" | jq '.peerDependencies // {} | keys | length')

	echo "    got ${version}"
	echo "    has ${transitive_count} dependencies"
	echo "    has ${peer_count} peers"

	counts_transitive="${counts_transitive}${transitive_count}
"
	counts_peer="${counts_peer}${peer_count}
"
	considered_packages="${considered_packages}${package}
"

	echo '  DEB cd ..'
	cd ..
done < <(printf '%s\n' "${packages}")
considered_packages="$(printf "%s" "${considered_packages}")"

echo '*** start original list of packages ***'
echo "${packages}" | sed 's/^/  /'
echo '***  end  original list of packages ***'

echo '*** start considered list of packages ***'
echo "${considered_packages}" | sed 's/^/  /'
echo '***  end  considered list of packages ***'

echo ''
echo '== COMPUTING STATS =='
transitive_count=0
transitive_sum=0
while IFS= read -r n; do
	echo "  tran: $n"
	transitive_count=$((transitive_count + 1))
	transitive_sum=$((transitive_sum + n))
done <<<"$(printf "%s\n" "$counts_transitive" | awk 'NF')"

peer_count=0
peer_sum=0
while IFS= read -r n; do
	echo "  peer: $n"
	peer_count=$((peer_count + 1))
	peer_sum=$((peer_sum + n))
done <<<"$(printf "%s\n" "$counts_peer" | awk 'NF')"

echo ''
echo '== RESULTS =='
echo "  avg # deps : $(echo "scale=2; ${transitive_sum} / ${transitive_count}" | bc) (=${transitive_sum}/${transitive_count})"
echo "  avg # peers: $(echo "scale=2; ${peer_sum} / ${peer_count}" | bc) (=${peer_sum}/${peer_count})"

edc=$(echo "scale=2; ${transitive_sum} / ${transitive_count}" | bc)
epc=$(echo "scale=2; ${peer_sum} / ${peer_count}" | bc)
pac=$(awk -v n="${epc}" 'function floor(x) { return (x == int(x)) ? x : (x < 0 ? int(x) - 1 : int(x)) } BEGIN{ print (10^floor(log(n) / log(10))) / 10 }')
edcu=$(awk -v pac="${pac}" -v edc="${edc}" 'BEGIN{ print pac * edc }')

eli=$(awk -v pac="${pac}" -v edc="${edc}" -v epc="${epc}" 'BEGIN{ printf "%.2f", ((1-pac) * (edc + epc * (1 + edc))) + (pac * edc) }')
ele=$(awk -v pac="${pac}" -v edcu="${edcu}" -v epc="${epc}" 'BEGIN{ printf "%.2f", ((1-pac) * (edcu + epc * (1 + edcu))) + (pac * (1 + edcu)) }')

echo "  E[L_i] = $eli = (1-${pac}) * (${edc} + ${epc} * (1+${edc})) + ${pac} * ${edc}"
echo "  E[L_e] = $ele = (1-${pac}) * (${edcu} + ${epc} * (1+${edcu})) + ${pac} * (1 + ${edcu})"

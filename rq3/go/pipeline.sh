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
echo "Evaluating dependency metrics of top ${TOTAL} Go modules, based on the metric '${METRIC}'"
echo "Using page size ${PAGE_SIZE}"

echo ''
echo '== COLLECTING PACKAGE NAMES =='
MAX_TRIES=100
packages=''
pages=$(( (TOTAL + PAGE_SIZE - 1) / PAGE_SIZE ))
for ((page=1; page<=pages; page++)); do
	echo "  Fetching page ${page} ..."

	url="https://packages.ecosyste.ms/api/v1/registries/proxy.golang.org/package_names?page=${page}&per_page=${PAGE_SIZE}&sort=${METRIC}"
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
echo '== DETERMINING TRANSITIVE COUNT =='
counts=''
while IFS= read -r package; do
    echo '  DEB go clean -modcache'
    go clean -modcache
	echo '  DEB rm -rf tmp/'
	rm -rf tmp/
	echo '  DEB mkdir tmp/'
	mkdir tmp/
	echo '  DEB cd tmp/'
	cd tmp/

	echo "  Evaluating '${package}' ..."
	go mod init example.com/m >/dev/null 2>&1
	if ! timeout 300s go get "${package}" >/dev/null 2>&1; then
		echo '    ! module not resolved'
		cd ..
		continue
	fi

	tmp=$(go list -m all 2>/dev/null)

	version=$(echo "$tmp" | awk 'NR == 2' | awk '{print $2}')
	if [[ -z "${version}" ]]; then
		echo '    ! module not found'
		cd ..
		continue
	fi

	transitive_count=$(echo "${tmp}" | awk 'NR > 2' | wc -l)
	if [[ -z "${transitive_count}" ]]; then
		echo '    ! dependency count could not be determined'
		echo '    === DEBUG START ==='  1>&2
		echo "${tmp}" | sed 's/^/    /' 1>&2
		echo '    ===  DEBUG END  ==='  1>&2
		cd ..
		continue
	fi

	echo "    got ${version}"
	echo "    has ${transitive_count} dependencies"

	counts="${counts}${transitive_count}
"

	cd ..
done <<<"${packages}"

echo ''
echo '== COMPUTING STATS =='
sum=0
count=0
while IFS= read -r n; do
	echo "  tran: $n"
	sum=$((sum + n))
	count=$((count + 1))
done <<<"$(printf "%s\n" "$counts" | awk 'NF')"

echo ''
echo '== RESULTS =='
echo "  avg # deps : $(echo "scale=2; ${sum} / ${count}" | bc) (=${sum}/${count})"

edc=$(echo "scale=2; ${sum} / ${count}" | bc)
epc='0'
pac='0.01'
edcu=$(awk -v pac="${pac}" -v edc="${edc}" 'BEGIN{ print pac * edc }')

eli=$(awk -v pac="${pac}" -v edc="${edc}" -v epc="${epc}" 'BEGIN{ printf "%.2f", ((1-pac) * (edc + epc * (1 + edc))) + (pac * edc) }')
ele=$(awk -v pac="${pac}" -v edcu="${edcu}" -v epc="${epc}" 'BEGIN{ printf "%.2f", ((1-pac) * (edcu + epc * (1 + edcu))) + (pac * (1 + edcu)) }')

echo "  E[L_i] = $eli = (1-${pac}) * (${edc} + ${epc} * (1+${edc})) + ${pac} * ${edc}"
echo "  E[L_e] = $ele = (1-${pac}) * (${edcu} + ${epc} * (1+${edcu})) + ${pac} * (1 + ${edcu})"

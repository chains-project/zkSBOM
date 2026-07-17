#!/bin/bash

## CLI
TOTAL="$1"
PAGE_SIZE="$2"
METRIC="$3"
RESULTS=''

if [[ -z ${TOTAL} || -z ${PAGE_SIZE} || -z ${METRIC} ]]; then
	echo 'USAGE:   ./pipeline.sh <TOTAL> <PAGE_SIZE> <METRIC>'
	echo 'EXAMPLE: ./pipeline.sh 500 100 downloads'
	echo ''
	echo ''
	echo '- TOTAL = n * PAGE_SIZE'
	echo '- METRIC in ["downloads", "last_synced_at", "latest_release_published_at", "dependencies_count", "versions_count"]'
	exit 0
fi


## Main
echo "Evaluating dependency metrics of top ${TOTAL} Docker containers, based on the metric '${METRIC}'"
echo "Using page size ${PAGE_SIZE}"

echo ''
echo '== COLLECTING CONTAINER DATA =='
MAX_TRIES=3
all_container_data=''
pages=$(( (TOTAL + PAGE_SIZE - 1) / PAGE_SIZE ))
for ((page=1; page<=pages; page++)); do
	echo "Fetching page ${page} ..."

	url="https://docker.ecosyste.ms/api/v1/packages?page=${page}&per_page=${PAGE_SIZE}&sort=${METRIC}&order=desc"
	tmp=""; ok=0; max=$MAX_TRIES
	for ((attempt=1; attempt<=max; attempt++)); do
		response=$(curl -sX 'GET' "${url}" -H 'accept: application/json')
		if tmp=$(echo "${response}" | jq -er 'if type=="array" then .[] else error("not an array") end' 2>/dev/null); then
			ok=1; break
		fi
		echo "  ! jq parse error (attempt ${attempt}/${max}) on: ${url}"
		echo '=== DEBUG START ===' 1>&2
		echo "${response}" 1>&2
		echo '===  DEBUG END  ===' 1>&2
		timeout=2
		[[ ${attempt} -lt ${max} ]] && echo "Sleeping for ${timeout}s" && sleep "${timeout}"
	done
	if [[ ${ok} -eq 0 ]]; then
		echo "  ! giving up on page ${page}"
		continue
	fi
	all_container_data="${all_container_data}$(echo "${tmp}" | jq -c)
"
done
all_container_data="$(printf "%s" "${all_container_data}")"

echo ''
echo "Got data for $(wc -l <<<"${all_container_data}") container(s)"
echo ''
echo '*** START CONTAINER DATA LIST ***'
echo "${all_container_data}"
echo '***  END  CONTAINER DATA LIST ***'

# ---------------------------------------------------------------------------- #

tmp_all_container_data=''
while IFS= read -r entry; do
	echo "Processing '$(echo "${entry}" | head -c 128)' ..."

	DOWNLOADS=$(echo ${entry} | jq -r '.downloads')
	if [[ "${DOWNLOADS}" == "null" ]]; then
		echo '  ! no download statisitics for this entry from ecosyste.ms'
		continue
	fi

	tmp_all_container_data+="${entry}
"
done <<<"${all_container_data}"
all_container_data="$(printf "%s" "${tmp_all_container_data}")"

echo ''
echo "Got data for $(wc -l <<<"${all_container_data}") container(s)"
echo ''
echo '*** START CONTAINER DATA LIST ***'
while IFS= read -r line; do
	echo "$(echo "${line}" | head -c 128) ..."
done <<<"${all_container_data}"
echo '***  END  CONTAINER DATA LIST ***'

# ---------------------------------------------------------------------------- #

echo ''
echo '== FILTERING DATA FOR ANY DEPENDENCIES ACCROSS ALL CONTAINERS =='
container_data=''
while IFS= read -r container; do
	echo "Processing '${container}' ..."

	if [[ "$(jq -r '.dependencies_count' <<<"${container}")" == "null" ]]; then
		continue
	fi

	container_data="${container_data}$(echo "${container}" | jq -c '{name, dependencies_count}')
"
done <<<"${all_container_data}"
container_data="$(printf "%s" "${container_data}")"

echo ''
echo "Left with $(wc -l <<<"${container_data}") container(s) after filtering"
echo ''
echo '*** START CONTAINER DATA LIST ***'
echo "${container_data}"
echo '***  END  CONTAINER DATA LIST ***'

echo ''
echo '== EXTRACTING NUMBERS ACROSS ALL CONTAINERS AND DEPENDENCIES =='
all=''
non_zero=''
while IFS= read -r container; do
	echo "Processing '${container}' ..."

	dependencies_count=$(echo "$container" | jq -r '.dependencies_count')
	all="${all}${dependencies_count}
"

	if [[ "$dependencies_count" == "0" ]]; then
		continue
	fi

	non_zero="${non_zero}${dependencies_count}
"
done <<<"${container_data}"
all="$(printf "%s" "${all}")"
non_zero="$(printf "%s" "${non_zero}")"

all_size=$(wc -l <<<"${all}")
non_zero_size=$(wc -l <<<"${non_zero}")

echo ''
echo "     all #: ${all_size}"
echo "non-zero #: ${non_zero_size}"
echo ''
echo '*** START ALL DEPENENCIES COUNTS ***'
echo "${all}"
echo '***  END  ALL DEPENENCIES COUNTS ***'
echo ''
echo '*** START NON-ZERO DEPENENCIES COUNTS ***'
echo "${non_zero}"
echo '***  END  NON-ZERO DEPENENCIES COUNTS ***'

echo ''
echo '== COMPUTING RESULTS ACROSS ALL CONTAINERS AND DEPENDENCIES =='
all_total=0
if [[ -n "${all}" ]]; then
	while IFS= read -r line; do
		echo "Computing total for all containers, adding ${line} to ${all_total} ..."
		all_total=$(( $all_total + $line ))
	done <<<"${all}"
fi

non_zero_total=0
if [[ -n "${non_zero}" ]]; then
	while IFS= read -r line; do
		echo "Computing total for non-zero dependency containers, adding ${line} to ${non_zero_total} ..."
		non_zero_total=$(( $non_zero_total + $line ))
	done <<<"${non_zero}"
fi

echo ''
tmp="avg #            deps overall : $(echo "scale=2; ${all_total} / ${all_size}" | bc) (= ${all_total} deps / ${all_size} containers with deps info)"
echo "$tmp"
RESULTS="${RESULTS}
$(echo "$tmp")"

tmp="avg # (non-zero) deps overall : $(echo "scale=2; ${non_zero_total} / ${non_zero_size}" | bc) (= ${non_zero_total} deps / ${non_zero_size} containers with >0 deps)"
echo "$tmp"
RESULTS="${RESULTS}
$(echo "$tmp")"

# ---------------------------------------------------------------------------- #

echo ''
echo '== FILTERING DATA FOR ECOSYSTEM SPECIFIC DEPENDENCY STATS =='
container_data=''
while IFS= read -r container; do
	echo "Processing '${container}' ..."

	if [[ "$(jq -r '.latest_release_number' <<<"${container}")" == "null" ]]; then
		continue
	fi

	container_data="${container_data}$(echo "${container}" | jq -c '{name, latest_release_number, url}')
"
done <<<"${all_container_data}"
container_data="$(printf "%s" "${container_data}")"

echo ''
echo "Left with $(wc -l <<<"${container_data}") container(s) after filtering"
echo ''
echo '*** START CONTAINER DATA LIST ***'
echo "${container_data}"
echo '***  END  CONTAINER DATA LIST ***'

echo ''
echo '== EXTRACTING ECOSYSTEM SPECIFIC DEPENDENCY STATS =='
all=''
non_zero=''
while IFS= read -r container; do
	echo "Collecting dependency data for '${container}' ..."

	url=$(echo "$container" | jq -r '.url')
	latest_release_number=$(echo "$container" | jq -r '.latest_release_number')

	url="${url}/versions/${latest_release_number}"
	response=$(curl -sX 'GET' "${url}" -H 'accept: application/json')

	dependencies=$(echo "${response}" | jq -c '.dependencies')

	all="${all}${dependencies}
"
	if [[ "${dependencies}" == "[]" ]]; then
		continue
	fi
	non_zero="${non_zero}${dependencies}
"
done <<<"${container_data}"
all="$(printf "%s" "${all}")"
non_zero="$(printf "%s" "${non_zero}")"

all_size=$(wc -l <<<"${all}")
non_zero_size=$(wc -l <<<"${non_zero}")

echo ''
echo "     all #: ${all_size}"
echo "non-zero #: ${non_zero_size}"
echo ''
echo '*** START ALL DEPENENCIES LISTS ***'
while IFS= read -r line; do
	echo "$(echo "${line}" | head -c 128) ..."
done <<<"${all}"
echo '***  END  ALL DEPENENCIES LISTS ***'
echo ''
echo '*** START NON-ZERO DEPENENCIES LISTS ***'
while IFS= read -r line; do
	echo "$(echo "${line}" | head -c 128) ..."
done <<<"${non_zero}"
echo '***  END  NON-ZERO DEPENENCIES LISTS ***'

for ecosystem in cargo golang maven npm; do
	echo ''
	echo "== EXTRACTING ECOSYSTEM (${ecosystem}) SPECIFIC DEPENDENCIWA =="

	all_for_ecosystem=''
	non_zero_for_ecosystem=''
	while IFS= read -r line; do
		echo "Processing '$(echo "${line}" | head -c 128)' ..."

		dependencies="$(echo "${line}" | jq -c '[.[] | select(.ecosystem == "'${ecosystem}'")]')"
		all_for_ecosystem="${all_for_ecosystem}${dependencies}
"
		if [[ "${dependencies}" == "[]" ]]; then
			continue
		fi
		non_zero_for_ecosystem="${non_zero_for_ecosystem}${dependencies}
"
	done <<<"${non_zero}"
	all_for_ecosystem="$(printf "%s" "${all_for_ecosystem}")"
	non_zero_for_ecosystem="$(printf "%s" "${non_zero_for_ecosystem}")"

	all_for_ecosystem_size=$(wc -l <<<"${all_for_ecosystem}")
	non_zero_for_ecosystem_size=$(wc -l <<<"${non_zero_for_ecosystem}")

	echo ''
	echo "     all #: ${all_for_ecosystem_size}"
	echo "non-zero #: ${non_zero_for_ecosystem_size}"
	echo ''
	echo "*** START ALL DEPENENCIES LISTS FOR ${ecosystem} ***"
	while IFS= read -r line; do
		echo "$(echo "${line}" | head -c 128) ..."
	done <<<"${all_for_ecosystem}"
	echo "***  END  ALL DEPENENCIES LISTS FOR ${ecosystem} ***"
	echo ''
	echo "*** START NON-EMPTY DEPENENCIES LISTS FOR ${ecosystem} ***"
	while IFS= read -r line; do
		echo "$(echo "${line}" | head -c 128) ..."
	done <<<"${non_zero_for_ecosystem}"
	echo "***  END  NON-EMPTY DEPENENCIES LISTS FOR ${ecosystem} ***"

	echo ''
	echo "== EXTRACTING NUMBER OF ${ecosystem} DEPENDENCIES =="
	all_counts=''
	non_zero_counts=''
	while IFS= read -r line; do
		echo "Processing '${line}' ..."

		dependencies_count=$(echo "$line" | jq 'length')
		all_counts="${all_counts}${dependencies_count}
"
		if [[ "$dependencies_count" == "0" ]]; then
			continue
		fi
		non_zero_counts="${non_zero_counts}${dependencies_count}
"
	done <<<"${all_for_ecosystem}"
	all_counts="$(printf "%s" "${all_counts}")"
	non_zero_counts="$(printf "%s" "${non_zero_counts}")"

	all_counts_size=$(wc -l <<<"${all_counts}")
	non_zero_counts_size=$(wc -l <<<"${non_zero_counts}")

	echo ''
	echo "     all counts #: ${all_counts_size}"
	echo "non-zero counts #: ${non_zero_counts_size}"
	echo ''
	echo "*** START ALL DEPENENCIES COUNTS FOR ${ecosystem} ***"
	echo "${all_counts}"
	echo "***  END  ALL DEPENENCIES COUNTS FOR ${ecosystem} ***"
	echo ''
	echo "*** START NON-ZERO DEPENENCIES COUNTS FOR ${ecosystem} ***"
	echo "${non_zero_counts}"
	echo "***  END  NON-ZERO DEPENENCIES COUNTS FOR ${ecosystem} ***"

	echo ''
	echo "== COMPUTING RESULTS FOR ${ecosystem} =="
	all_counts_total=0
	if [[ -n "${all_counts}" ]]; then
		while IFS= read -r line; do
			echo "Computing total for all containers, adding ${line} to ${all_counts_total} ..."
			all_counts_total=$(( $all_counts_total + $line ))
		done <<<"${all_counts}"
	fi

	non_zero_counts_total=0
	if [[ -n "${non_zero_counts}" ]]; then
		while IFS= read -r line; do
			echo "Computing total for non-zero dependency containers, adding ${line} to ${non_zero_total} ..."
			non_zero_counts_total=$(( $non_zero_counts_total + $line ))
		done <<<"${non_zero_counts}"
	fi

	tmp="avg #            deps for ${ecosystem} : $(echo "scale=2; ${all_counts_total} / ${all_counts_size}" | bc) (= ${all_counts_total} deps / ${all_counts_size} containers with any deps)"
	echo "$tmp"
	RESULTS="${RESULTS}
$(echo "$tmp")"

	tmp="avg # (non-zero) deps for ${ecosystem} : $(echo "scale=2; ${non_zero_counts_total} / ${non_zero_counts_size}" | bc) (= ${non_zero_counts_total} deps / ${non_zero_counts_size} containers with >0 ${ecosystem} deps)"
	echo "$tmp"
	RESULTS="${RESULTS}
$(echo "$tmp")"
done

echo ''
echo '-------------------------------------------------------------------------'
echo ''

echo "$RESULTS"

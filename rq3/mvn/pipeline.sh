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
echo "Evaluating dependency metrics of top ${TOTAL} Maven (Maven Central) packages, based on the metric '${METRIC}'"
echo "Using page size ${PAGE_SIZE}"

echo ''
echo '== COLLECTING PACKAGE NAMES =='
packages=''
pages=$(( (TOTAL + PAGE_SIZE - 1) / PAGE_SIZE ))
for ((page=1; page<=pages; page++)); do
	echo "Fetching page ${page} ..."

	url="https://packages.ecosyste.ms/api/v1/registries/repo1.maven.org/package_names?page=${page}&per_page=${PAGE_SIZE}&sort=${METRIC}"
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
counts_transitive=''
counts_peer=''
while IFS= read -r package; do
	rm -rf tmp/
	mkdir tmp/
	cd tmp/

  echo "Evaluating '${package}' ..."

	# Maven requires an explicit version in pom.xml; fetch it from the registry
	encoded=$(jq -rn --arg p "${package}" '$p | @uri')
	version=$(curl -s "https://packages.ecosyste.ms/api/v1/registries/repo1.maven.org/packages/${encoded}" \
		| jq -r '.latest_release_number // .latest_stable_release_number // "LATEST"')

	group_id=$(echo "${package}" | cut -d: -f1)
	artifact_id=$(echo "${package}" | cut -d: -f2)

	cat > pom.xml <<POMEOF
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>analysis</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>${group_id}</groupId>
      <artifactId>${artifact_id}</artifactId>
      <version>${version}</version>
    </dependency>
  </dependencies>
</project>
POMEOF

	mvn_stderr=$(mktemp)
	timeout 60s mvn -B -q -Dmaven.repo.local="${HOME}/.m2/repository" org.apache.maven.plugins:maven-dependency-plugin:3.10.0:tree -DoutputType=json -DoutputFile=dependencies.json >/dev/null 2>"${mvn_stderr}"
	mvn_exit=$?
	if [[ ${mvn_exit} -eq 124 ]]; then
		echo '  ! timed out'
		rm -f "${mvn_stderr}"
		cd ..
		continue
	elif [[ ${mvn_exit} -ne 0 ]]; then
		echo "  ! maven failed: $(grep -m1 'ERROR\|Could not\|Failed' "${mvn_stderr}" || echo 'unknown error')"
		rm -f "${mvn_stderr}"
		cd ..
		continue
	fi
	rm -f "${mvn_stderr}"

	transitive_count=$(jq '
		[.. | objects | select(has("groupId") and (.scope? != "test"))] |
		unique_by(.groupId + ":" + .artifactId) |
		length - 2
	' dependencies.json)
	# length counts all nodes including the tree root (com.example:analysis) and the
	# package under analysis itself, so subtract 2 to get only its transitive deps
	if [[ "${transitive_count}" -lt 0 ]]; then
		echo '  ! dependency count could not be determined'
		echo ''
		echo '=== DEBUG START ==='
		cat dependencies.json
		echo '===  DEBUG END  ==='
		cd ..
		continue
	fi

	group_path=$(echo "${group_id}" | tr '.' '/')
	pom_file="${HOME}/.m2/repository/${group_path}/${artifact_id}/${version}/${artifact_id}-${version}.pom"
	peer_count=0
	if [[ -f "${pom_file}" ]]; then
		peer_count=$(python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('${pom_file}')
root = tree.getroot()
tag = root.tag
ns = tag.split('}')[0] + '}' if tag.startswith('{') else ''
count = 0
for dep in root.findall(f'.//{ns}dependencies/{ns}dependency'):
    scope = dep.find(f'{ns}scope')
    if scope is not None and scope.text == 'provided':
        count += 1
print(count)
" 2>/dev/null || echo 0)
	fi

	echo "  got ${version}"
	echo "  has ${transitive_count} dependencies"
	echo "  has ${peer_count} peers"

	counts_transitive="${counts_transitive}${transitive_count}
"
	counts_peer="${counts_peer}${peer_count}
"

	cd ..
done <<<"$(printf "%s\n" "$packages" | awk 'NF')"

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

#!/usr/bin/env bash
set -e

CORGEA_URL="http://localhost:5000"
CMD="$@"
RUN_ID=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) || true
FILES_FOR_UPLOAD=()
CORGEA_REPORT_NAME="corgea_report_$RUN_ID.json"

check_requirements() {
  if ! command -v semgrep &> /dev/null
  then
      echo "semgrep could not be found"
      exit
  fi

  if ! command -v snyk &> /dev/null
  then
      echo "snyk could not be found"
      exit
  fi

  if [ -z "$CMD" ]
  then
    echo "No command provided"
    exit
  fi

  if [ -z "$CORGEA_TOKEN" ]
  then
    echo "CORGEA_TOKEN is not set"
    exit
  fi
}

parse_semgrep_report() {
  FILES=$(cat $CORGEA_REPORT_NAME | tr "," "\n" | grep '"path": ' | uniq)

  for i in $FILES
  do
    if [[ ! $i == *'"path"'* ]]; then
      FILES_FOR_UPLOAD+=($(echo $i | tr -d "\""))
    fi
  done
}

parse_snyk_report() {
  echo "Parsing snyk repot"
  FILES=$(cat $CORGEA_REPORT_NAME | grep '"uri": ' | sed 's/ *$//g' | tr -d '[:blank:]' | uniq)

  for i in $FILES
  do
    path=($(echo $i | sed 's/"uri"://g' | tr -d "\"" | tr -d ","))
    found=0

    for j in "${FILES_FOR_UPLOAD[@]}"; do
        if [[ $j == $path ]]; then
            found=1
            break
        fi
    done

    if [[ $found -eq 0 ]]; then
      FILES_FOR_UPLOAD+=("$path")
    fi
  done
}

run_scan() {
  echo "Starting Corgea run_id: $RUN_ID"

  cmd_binary=$(echo $CMD | awk '{print $1}')

  echo "Running scan with commmand '$CMD'"
  $($CMD > $CORGEA_REPORT_NAME) || true
  REPORT=$(cat $CORGEA_REPORT_NAME)

  if [[ $cmd_binary == "snyk" ]]; then
    parse_snyk_report
  elif [[ $cmd_binary == "semgrep" ]]; then
    parse_semgrep_report
  fi

  echo "Finished running scan."
}

upload_results() {
  echo "Uploading results to Corgea"

  echo $REPORT | curl -s -X POST -H "Content-Type: application/json" -d @- "$CORGEA_URL/api/cli/scan-upload?token=$CORGEA_TOKEN&run_id=$RUN_ID" > /dev/null

  for f in "${FILES_FOR_UPLOAD[@]}"
  do
    curl -s -X POST -F "file=@$f" "$CORGEA_URL/api/cli/code-upload?token=$CORGEA_TOKEN&run_id=$RUN_ID" > /dev/null
  done

  echo "View results at: https://corgea.app/$RUN_ID"
}

run_corgea() {
  check_requirements
  run_scan
  upload_results
}

run_corgea

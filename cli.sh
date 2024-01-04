#!/usr/bin/env bash
set -e

: ${CORGEA_URL:="https://www.corgea.app"}
CMD="$@"
CMD_BINARY=$(echo $CMD | awk '{print $1}')
VALID_BINARIES=(snyk semgrep)
RUN_ID=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) || true
FILES_FOR_UPLOAD=()
CORGEA_REPORT_NAME="corgea_report_$RUN_ID.json"
PROJECT_NAME=$(basename $(pwd))

check_requirements() {
  found=0
  for i in "${VALID_BINARIES[@]}"; do
    if [ "$i" == "$CMD_BINARY" ]; then
        found=1
        break
    fi
  done

  if [ $found -eq 0 ]; then
    echo "Invalid command provided. Supported SAST tools are snyk and semgrep currently."
    exit
  fi

  if ! command -v $CMD_BINARY &> /dev/null
  then
      echo "$CMD_BINARY could not be found. Is it installed?"
      exit
  fi

  if [ -z "$CMD" ]
  then
    echo "No command provided."
    exit
  fi

  if [ -z "$CORGEA_TOKEN" ]
  then
    echo "CORGEA_TOKEN is not set."
    exit
  fi

  VERIFY_TOKEN=$(curl -sS "$CORGEA_URL/api/cli/verify/$CORGEA_TOKEN")

  if [[ $VERIFY_TOKEN == *"error"* ]]; then
    echo "Invalid token provided."
    exit
  fi
}

parse_semgrep_report() {
  if [[ $REPORT_ERROR == *"semgrep login"* ]]; then
    echo "Please log into semgrep first. Run 'semgrep login' to get started."
    exit
  fi

  FILES=$(cat $CORGEA_REPORT_NAME | tr "," "\n" | grep '"path": ' | uniq)

  for i in $FILES
  do
    if [[ ! $i == *'"path"'* ]]; then
      FILES_FOR_UPLOAD+=($(echo $i | tr -d "\""))
    fi
  done
}

parse_snyk_report() {
  if [[ $REPORT == *"MissingApiTokenError"* ]]; then
    echo "'snyk' requires an authenticated account. Please run 'snyk auth' and try again."
    exit
  fi

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
  $($CMD > $CORGEA_REPORT_NAME 2> corgea_report_error.log) || true
  REPORT=$(cat $CORGEA_REPORT_NAME)
  REPORT_ERROR=$(cat corgea_report_error.log)

  if [[ $CMD_BINARY == "snyk" ]]; then
    parse_snyk_report
  elif [[ $CMD_BINARY == "semgrep" ]]; then
    parse_semgrep_report
  fi

  echo "Finished running scan."
}

upload_results() {
  echo "Uploading results to Corgea."

  cat $CORGEA_REPORT_NAME | curl -sS -X POST -H "Content-Type: application/json" -d @- "$CORGEA_URL/api/cli/scan-upload?token=$CORGEA_TOKEN&run_id=$RUN_ID&engine=$CMD_BINARY&project=$PROJECT_NAME" > /dev/null

  if [ -f .git/config ]; then
    curl -sS -X POST -F "file=@.git/config" "$CORGEA_URL/api/cli/git-config-upload?token=$CORGEA_TOKEN&run_id=$RUN_ID" > /dev/null
  fi

  for f in "${FILES_FOR_UPLOAD[@]}"
  do
    curl -sS -X POST -F "file=@$f" "$CORGEA_URL/api/cli/code-upload?token=$CORGEA_TOKEN&run_id=$RUN_ID&path=$f" > /dev/null
  done

  echo "Scan upload finished."
  echo "View results at: $CORGEA_URL"
}

run_corgea() {
  check_requirements
  run_scan
  upload_results
}

run_corgea

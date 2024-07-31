#!/bin/bash

VERSION=0.5.49
HDIR=$(dirname "$0")
DEBUG=0
INFOMAIL=1
# INFOMAIL 1=ALWAYS (DEFAULT), 2=WARN, 3=ERROR
SENDM=0
PRINT_CURL=1  # Setta a 1 per stampare la stringa curl eseguita
sleep 1

if [ ! $SLEEP ]; then
 SLEEP=60
fi

if [[ $EUID -ne 0 ]]; then
 echo "This script must be run as root"
 logger -t vee-mail "This script must be run as root"
 exit 1
fi

. $HDIR/vee-mail.config

API_LOGIN_ENDPOINT="/api/auth/login"
API_LOGOUT_ENDPOINT="/api/auth/logout"
API_JOBS_ENDPOINT="/api/jobs/"

# Funzione per ottenere il token
get_api_token() {
  local response=$(curl -s -X POST "$API_URL_BASE$API_LOGIN_ENDPOINT" -H "Accept: application/json" -H "Content-Type: application/json" -d "{\"username\": \"$API_USERNAME\", \"password\": \"$API_PASSWORD\"}")
  echo $(echo $response | jq -r '.token')
}

# Funzione per effettuare il logout
logout_api() {
  local response=$(curl -s -X POST "$API_URL_BASE$API_LOGOUT_ENDPOINT" -H "Accept: application/json" -H "Authorization: Bearer $API_KEY")
  echo $response
  if [ "$response" == "200" ]; then
    echo "Logout eseguito con successo"
  else
    echo "Errore durante il logout: $response"
  fi
}

API_KEY=$(get_api_token)

if [ -z "$API_KEY" ]; then
 echo "Error: Unable to obtain API token"
 exit 1
fi

STARTEDFROM=$(ps -p $PPID -hco cmd)
if [ "$1" == "--bg" ]; then
 if [ "$STARTEDFROM" == "veeamjobman" ]; then
  logger -t vee-mail "waiting for 30 seconds"
  sleep $SLEEP
 fi
fi

VC=$(which veeamconfig)
if [ ! "$VC" ]; then
 echo "No Veeam Agent for Linux installed!"
 logger -t vee-mail "No Veeam Agent for Linux installed!"
 exit
fi

VV=$(veeamconfig -v|cut -c2)

YUM=$(which yum)

SQLITE=$(which sqlite3)
if [ "$SQLITE" != "/usr/bin/sqlite3" ] && [ "$SQLITE" != "/bin/sqlite3" ]; then
 if [ "$YUM" ]; then
  yum install -y sqlite3
 else
  apt-get install -y sqlite3
 fi
fi

CURL=$(which curl)
if [ ! "$CURL" ]; then
 if [ "$YUM" ]; then
  yum install -y curl
 else
  apt-get install -y curl
 fi
fi

if [ $SKIPVERSIONCHECK -ne 1 ]; then
 if [ "$CURL" ]; then
  AKTVERSION=$($CURL -m2 -f -s https://raw.githubusercontent.com/grufocom/vee-mail/master/vee-mail.sh --stderr - | grep "^VERSION=" | awk -F'=' '{print $2}')
  if [ "$AKTVERSION" ]; then
   HIGHESTVERSION=$(echo -e "$VERSION\n$AKTVERSION" | sort -rV | head -n1)
   if [ "$VERSION" != "$HIGHESTVERSION" ]; then
    logger -t vee-mail "new Vee-Mail version $AKTVERSION available"
    AKTVERSION="\(new Vee-Mail version $AKTVERSION available\)"
   else
    AKTVERSION=""
   fi
  fi
 else
  AKTVERSION="\(you need curl to use the upgrade check, please install\)"
 fi
else
 VERSION="$VERSION \(upgrade check disabled\)"
fi

AGENT=$($VC -v)
# get last session id
if [ $VV -ge 6 ]; then
 SESSID=$($VC session list|grep -v "Total amount"|tail -1|awk '{print $(NF-7)}')
else
 SESSID=$($VC session list|grep -v "Total amount"|tail -1|awk '{print $(NF-5)}')
fi
SESSID=${SESSID:1:${#SESSID}-2}

# state 1=Running, 6=Success, 7=Failed, 9=Warning
# get data from sqlite db
if [ $VV -ge 6 ]; then
 SESSDATA=$(sqlite3 /var/lib/veeam/veeam_db.sqlite  "select start_time_utc, end_time_utc, state, progress_details, job_id, job_name from JobSessions order by start_time_utc DESC limit 1;")
else
 SESSDATA=$(sqlite3 /var/lib/veeam/veeam_db.sqlite  "select start_time, end_time, state, progress_details, job_id, job_name from JobSessions order by start_time DESC limit 1;")
fi

STARTTIME=$(echo $SESSDATA|awk -F'|' '{print $1}')
ENDTIME=$(echo $SESSDATA|awk -F'|' '{print $2}')
STATE=$(echo $SESSDATA|awk -F'|' '{print $3}')
DETAILS=$(echo $SESSDATA|awk -F'|' '{print $4}'| jq -Rs .)
JOBID=$(echo $SESSDATA|awk -F'|' '{print $5}')
JOBNAME=$(echo $SESSDATA|awk -F'|' '{print $6}')

if [ $DEBUG -gt 0 ]; then
 echo -e -n "STARTTIME: $STARTTIME, ENDTIME: $ENDTIME, STATE: $STATE, JOBID: $JOBID, JOBNAME: $JOBNAME\nDETAILS: $DETAILS\n"
 logger -t vee-mail "STARTTIME: $STARTTIME, ENDTIME: $ENDTIME, STATE: $STATE, JOBID: $JOBID, JOBNAME: $JOBNAME\nDETAILS: $DETAILS"
fi

PROCESSED=$(echo $DETAILS|awk -F'processed_data_size_bytes="' '{print $2}'|awk -F'"' '{print $1}')
PROCESSED=$(awk "BEGIN {printf \"%.1f\n\", $PROCESSED/1024/1024/1024}")" GB"
READ=$(echo $DETAILS|awk -F'read_data_size_bytes="' '{print $2}'|awk -F'"' '{print $1}')
READ=$(awk "BEGIN {printf \"%.1f\n\", $READ/1024/1024/1024}")" GB"
TRANSFERRED=$(echo $DETAILS|awk -F'transferred_data_size_bytes="' '{print $2}'|awk -F'"' '{print $1}')
TRANSFERRED=$(awk "BEGIN {printf \"%.1f\n\", $TRANSFERRED/1024/1024/1024}")" GB"
SPEED=$(echo $DETAILS|awk -F'processing_speed="' '{print $2}'|awk -F'"' '{print $1}')
SPEED=$(awk "BEGIN {printf \"%.1f\n\", $SPEED/1024/1024}")
SOURCELOAD=$(echo $DETAILS|awk -F'source_read_load="' '{print $2}'|awk -F'"' '{print $1}')
SOURCEPLOAD=$(echo $DETAILS|awk -F'source_processing_load="' '{print $2}'|awk -F'"' '{print $1}')
NETLOAD=$(echo $DETAILS|awk -F'network_load="' '{print $2}'|awk -F'"' '{print $1}')
TARGETLOAD=$(echo $DETAILS|awk -F'target_write_load="' '{print $2}'|awk -F'"' '{print $1}')

if [ "$SOURCELOAD" -gt "$SOURCEPLOAD" ] && [ "$SOURCELOAD" -gt "$NETLOAD" ] && [ "$SOURCELOAD" -gt "$TARGETLOAD" ]; then
 BOTTLENECK="Source"
elif [ "$SOURCEPLOAD" -gt "$SOURCELOAD" ] && [ "$SOURCEPLOAD" -gt "$NETLOAD" ] && [ "$SOURCEPLOAD" -gt "$TARGETLOAD" ]; then
 BOTTLENECK="Source CPU"
elif [ "$NETLOAD" -gt "$SOURCELOAD" ] && [ "$NETLOAD" -gt "$SOURCEPLOAD" ] && [ "$NETLOAD" -gt "$TARGETLOAD" ]; then
 BOTTLENECK="Network"
else
 BOTTLENECK="Target"
fi

let DUR=ENDTIME-STARTTIME DURATIONSEC=DUR%60 DURATIONMIN=\(DUR-DURATIONSEC\)/60%60 DURATIONHOUR=\(DUR-DURATIONSEC-\(DURATIONMIN*60\)\)/3600
DURATION=$(printf "%d:%02d:%02d\n" $DURATIONHOUR $DURATIONMIN $DURATIONSEC)
START=$(date -d "@$STARTTIME" +"%A, %d %B %Y %H:%M:%S")
END=$(date -d "@$ENDTIME" +"%A, %d.%m.%Y %H:%M:%S")
STIME=$(date -d "@$STARTTIME" +"%H:%M:%S")
ETIME=$(date -d "@$ENDTIME" +"%H:%M:%S")

# Preparare il payload JSON
payload=$(cat <<EOF
{
  "start_time": "$STARTTIME",
  "details": "",
  "end_time": "$ENDTIME",
  "state": "$STATE",
  "job_id": "$JOBID",
  "job_name": "$JOBNAME",
  "processed": "$PROCESSED",
  "read": "$READ",
  "transferred": "$TRANSFERRED",
  "speed": "$SPEED",
  "source_load": "$SOURCELOAD",
  "source_processing_load": "$SOURCEPLOAD",
  "network_load": "$NETLOAD",
  "target_load": "$TARGETLOAD",
  "bottleneck": "$BOTTLENECK",
  "duration": "$DURATION"
}
EOF
)

# Costruire la stringa curl
curl_cmd="curl -s -o /dev/null -w \"%{http_code}\" -X POST \"$API_URL_BASE$API_JOBS_ENDPOINT\" -H \"Accept: application/json\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer $API_KEY\" -d '$payload'"

# Stampare la stringa curl se PRINT_CURL è impostato a 1
if [ $PRINT_CURL -eq 1 ]; then
  echo "Eseguendo il comando curl:"
  echo $curl_cmd
fi

# Eseguire il comando curl
response=$(eval $curl_cmd)

if [ "$response" -eq 200 ]; then
  echo "Dati inviati con successo!"
else
  echo "Errore durante l'invio dei dati: $response"
fi

# Effettuare il logout
logout_api

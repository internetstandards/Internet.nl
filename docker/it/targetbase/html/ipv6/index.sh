#!/bin/bash
OUTPUT_PATH=./http_response
NUM_LINES=$(cat ${OUTPUT_PATH} | wc -l)
FROM_LINE=1
LINES_TO_SEND_AT_ONCE=20
SLEEP_BETWEEN_SENDS=0.1s
while [ ${FROM_LINE} -lt ${NUM_LINES} ]; do
	tail -n +${FROM_LINE} ./http_response | head -n ${LINES_TO_SEND_AT_ONCE}
	sleep ${SLEEP_BETWEEN_SENDS}
	let "FROM_LINE=FROM_LINE+LINES_TO_SEND_AT_ONCE"
done

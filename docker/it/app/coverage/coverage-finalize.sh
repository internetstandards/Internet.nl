#!/bin/bash
# Coverage setup based on: https://github.com/celery/celery/issues/3422
ENABLE_COVERAGE=${ENABLE_COVERAGE:-0}
if [ ${ENABLE_COVERAGE} -eq 1 ]; then
    echo
    echo ":: Terminating the Internet.nl app to trigger writing of coverage data to disk.."

    cd /app
    celery -A internetnl control shutdown
    pkill --signal SIGINT -f runserver

    echo "Waiting 5 seconds to allow coverage data files to be written.."
    sleep 5s

    echo
    echo ":: Coverage diagnostics.."
    echo "Coverage data files produced:"
    cd /tmp/it-report/coverage-data
    ls -la

    echo "Coverage configuration:"
    cd /app
    coverage debug config

    echo
    echo ":: Coverage processing.."
    echo "Combining .coverage.xxx files into a single .coverage file.."
    coverage combine

    echo "Generating coverage reports.."
    coverage report
    coverage html -d /tmp/it-report/coverage-report
    coverage xml -o /tmp/it-report/coverage-report/coverage.xml
fi
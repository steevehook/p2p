#!/bin/bash

workdir=".coverage"
atomicOut="${workdir}/coverage.out"
textOut="${workdir}/coverage.txt"
htmlOut="${workdir}/coverage.html"
status=0

coverage() {
  packages=$(go list ./... | grep "/$(go list | xargs basename)/" | grep -Ev "(vendor)" | grep -Ev "(testutils)" | tr '\n' ',')
  mkdir -p "${workdir}"
  rm -rf "${workdir}:?/*"
  go test -v -timeout 99999s -race -count=1 -tags="${1}" -cover -covermode="atomic" -coverprofile="${atomicOut}" -count=1 -coverpkg="${packages}" ./... | tee "${textOut}"
  if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    status=1
  fi
  go tool cover -func="$atomicOut"
}

for i in "$@"; do
  case "${i}" in

  --unit)
    echo "running unit tests"
    coverage ""
    ;;

  --intgr)
    echo "running unit & integration tests"
    coverage "intgr"
    ;;

  --html)
    echo "generating html coverage report"
    coverage "intgr"
    go tool cover -html="${atomicOut}"
    go tool cover -html="${atomicOut}" -o="${htmlOut}"
    ;;

  *)
    echo >&2 "error: invalid option"
    status=1
    ;;

  esac
done

exit "${status}"

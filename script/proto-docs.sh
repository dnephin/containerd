#!/usr/bin/env bash
set -eux -o pipefail

for pkg in \
    'api/events' \
    'api/types' \
    'api/types/task' \
    'api/services/images/v1/' \
    'api/services/tasks/v1/' \
    'api/services/content/v1/' \
    'api/services/snapshot/v1/' \
    'api/services/namespaces/v1/' \
    'api/services/diff/v1/' \
    'api/services/version/v1/' \
    'api/services/events/v1/' \
    'api/services/leases/v1/' \
    'api/services/introspection/v1/' \
    'api/services/containers/v1/' \
; do
    name=$(basename $pkg)
    if [[ "$name" == "v1" ]]; then
        name=$(basename $(dirname $pkg))
    fi

    protoc \
        --plugin=protoc-gen-doc=/go/bin/protoc-gen-doc \
        --doc_out=./docs/grpc \
        --doc_opt=html,$name.html \
        --proto_path=/go/src/ \
        --proto_path=./protobuf/ \
        --proto_path=./vendor/github.com/gogo/protobuf/ \
        $PWD/$pkg/*.proto
done

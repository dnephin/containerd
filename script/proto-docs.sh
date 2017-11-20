#!/usr/bin/env bash
set -eux -o pipefail

mkdir -p docs/grpc

DOCROOT="${DOCROOT:$PWD}"
target=docs/grpc
templates=docs/grpc-templates
filemap="$templates/filemap.xml"

cp "$templates/index-header.html" "$target/index.html"


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
    protoc \
        --doc_out="root=$DOCROOT,filemap=$filemap:$target" \
        --proto_path=/go/src/ \
        --proto_path=./protobuf/ \
        --proto_path=./vendor/github.com/gogo/protobuf/ \
        $PWD/$pkg/*.proto
    cat "$target/index-item.html" >> "$target/index.html"
done

rm -f "$target/index-item.html"
cat "$templates/index-footer.html" >> "$target/index.html"

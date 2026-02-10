#!/bin/bash

# 1. Initialize the module (if not already done)
if [ ! -f go.mod ]; then
    echo "Initializing Go Module..."
    go mod init github.com/ldsec/crisp
fi

# 2. Fix the "lattigo_private" import to the public v2 version
echo "Rewriting Lattigo imports..."
# This finds all .go files and replaces the private string with the public one
find . -name "*.go" -exec sed -i 's|github.com/ldsec/lattigo_private|github.com/tuneinsight/lattigo/v2|g' {} +

# 3. Fix internal imports (pointing to the repo itself)
# If the code imports "github.com/ldsec/crisp/utils", we want it to look locally.
echo "Ensuring local imports work..."
# (No sed needed here usually, handled by go.mod replace directive later)

# 4. Force the specific 2021 version of Lattigo
echo "Downloading correct Lattigo dependencies..."
go get github.com/tuneinsight/lattigo/v2@v2.4.1

echo "Phase 1 Complete."
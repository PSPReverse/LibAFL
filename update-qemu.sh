#!/bin/bash

# File to modify
TARGET_FILE="crates/libafl_qemu/libafl_qemu_build/src/build.rs"

# Line number to replace
LINE_NUMBER=14

# Check if the file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "Error: File $TARGET_FILE does not exist."
    exit 1
fi
pushd ../qemu

# Check if the current directory is a Git repository
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo "Error: This is not a Git repository."
    exit 1
fi

# Check if the repository is clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: The repository has uncommitted changes."
    exit 1
fi

NEW_COMMIT_HASH=$(git rev-parse HEAD)
popd
# Replace the line with the new commit hash
sed -i "${LINE_NUMBER}s|\".*\"|\"$NEW_COMMIT_HASH\"|" "$TARGET_FILE"

echo "Updated QEMU_REVISION in $TARGET_FILE to $NEW_COMMIT_HASH"
git commit -a --amend --no-edit
git push -f
#!/bin/bash
# Bastillion v4 H2 database migration utility (imports into v5 or v6).
#
# Usage:
#   ./migrate.sh export <old-config-dir> <output-json-file>
#   ./migrate.sh import <new-config-dir> <input-json-file> --yes-replace-all-data
#
# <old-config-dir> / <new-config-dir> are directories containing BastillionConfig.properties
# and bastillion.jceks for that instance (the same directory Bastillion itself would be
# pointed at via -DCONFIG_DIR). The H2 file may live either at "<dir>/keydb/bastillion.mv.db"
# (the real app's default layout) or flatly at "<dir>/bastillion.mv.db".
#
# Standalone Maven project (see pom.xml / README.md): builds entirely on its own, no
# Bastillion build/install step needed first - it reuses Bastillion's AppConfig/
# EncryptionUtil via source symlinks (see src/main/java), compiled directly into this
# tool's own jar.

set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

JAR_URL="https://github.com/Loophole-LLC/Bastillion/releases/download/v5.0.0/bastillion-migrate-1.0.0.jar"
JAR_SHA256="0b2d315c4785a2b7edf91f917d2910faea524bcf65c814cd9777772368b85aa6"
JAR_CACHE="$SCRIPT_DIR/target/bastillion-migrate-1.0.0.jar"

verify_jar_sha256() {
    local file="$1" actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        echo "No sha256sum/shasum utility found, cannot verify jar checksum." >&2
        return 1
    fi
    [ "$actual" = "$JAR_SHA256" ]
}

if [ ! -f "$JAR_CACHE" ]; then
    echo "Downloading migration tool jar from $JAR_URL ..." >&2
    mkdir -p "$SCRIPT_DIR/target"
    if curl -fsSL -o "$JAR_CACHE" "$JAR_URL" && verify_jar_sha256 "$JAR_CACHE"; then
        :
    else
        echo "Download or checksum verification failed, discarding and falling back to local build." >&2
        rm -f "$JAR_CACHE"
    fi
fi

migrate_jars=("$SCRIPT_DIR"/target/bastillion-migrate-*.jar)
if [ "${#migrate_jars[@]}" -eq 0 ]; then
    echo "Building migration tool (mvn package)..." >&2
    (cd "$SCRIPT_DIR" && mvn -q package)
    migrate_jars=("$SCRIPT_DIR"/target/bastillion-migrate-*.jar)
fi
JAR="${migrate_jars[0]}"

# CONFIG_DIR must end with a path separator - AppConfig concatenates it directly with
# "BastillionConfig.properties" with no separator in between.
normalize_dir() {
    case "$1" in
        */) echo "$1" ;;
        *) echo "$1/" ;;
    esac
}

cmd="${1:-}"
case "$cmd" in
    export)
        if [ "$#" -ne 3 ]; then
            echo "Usage: $0 export <old-config-dir> <output-json-file>" >&2
            exit 1
        fi
        config_dir="$(normalize_dir "$2")"
        java -DCONFIG_DIR="$config_dir" -jar "$JAR" export "$config_dir" "$3"
        ;;
    import)
        if [ "$#" -ne 4 ]; then
            echo "Usage: $0 import <new-config-dir> <input-json-file> --yes-replace-all-data" >&2
            exit 1
        fi
        config_dir="$(normalize_dir "$2")"
        java -DCONFIG_DIR="$config_dir" -jar "$JAR" import "$config_dir" "$3" "$4"
        ;;
    *)
        echo "Usage: $0 export <old-config-dir> <output-json-file>" >&2
        echo "       $0 import <new-config-dir> <input-json-file> --yes-replace-all-data" >&2
        exit 1
        ;;
esac

#!/usr/bin/env bash
# Runs the genuine-CL oracle: the dex2jar'd NPCI Common Library checks the C implementation.
# Needs a CL classes jar (CL_JAR env or $1), produced from an app's CL dex via dex2jar.
# Pinned helper jars (BouncyCastle, org.json) are fetched into oracle/.jars on first run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LITE="$(dirname "$HERE")"
CL_JAR="${CL_JAR:-${1:-}}"
: "${JAVA_HOME:=/usr/lib/jvm/java-17-openjdk}"
export PATH="$JAVA_HOME/bin:$PATH"

if [[ -z "$CL_JAR" || ! -f "$CL_JAR" ]]; then
    echo "set CL_JAR to the dex2jar'd NPCI CL jar (see oracle notes)" >&2
    exit 2
fi

JARS="$HERE/.jars"
mkdir -p "$JARS"
BC="$JARS/bcprov-jdk18on-1.78.1.jar"
JSON="$JARS/json-20240303.jar"
[[ -f "$BC" ]] || curl -sSL -o "$BC" "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar"
[[ -f "$JSON" ]] || curl -sSL -o "$JSON" "https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar"

BUILD="$HERE/.build"
rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -cp "$BC" -d "$BUILD" $(find "$HERE/stubs" "$HERE/src" -name '*.java')

make -C "$LITE" oracle-tools >/dev/null
CROSS="$BUILD/crosscheck.json"
CROSS_CL="$BUILD/crosscheck_cl.json"
"$LITE/build/gen_oracle_crosscheck" "$CROSS"

CP="$BC:$BUILD:$CL_JAR:$JSON"
echo "== vectors vs genuine CL =="
java -Xverify:none -cp "$CP" LiteOracle "$LITE/vectors/vectors.json"
echo "== bidirectional cross-check =="
java -Xverify:none -cp "$CP" LiteCrossCheck "$CROSS" "$CROSS_CL"
"$LITE/build/check_cl_vault" "$CROSS_CL"

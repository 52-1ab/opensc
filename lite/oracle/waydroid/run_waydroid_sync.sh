#!/usr/bin/env bash
# Runs the GENUINE NPCI CL sync (Oooo000.registerState) inside a real Android runtime (waydroid),
# and checks accept/reject against the C wallet. This is the device-backed form of criterion 4.
#
# Needs an AUTHORISED adb device (waydroid), the genuine CL dex, and d8. From this sandbox adb
# stayed "offline" and `waydroid shell` needs root, so a human runs this once adb shows "device":
#   waydroid session start                 # if not running
#   adb connect 192.168.240.112:5555       # then authorise on the waydroid screen
#   CL_DEX=<classes with org/npci CL> ./run_waydroid_sync.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LITE="$(cd "$HERE/../.." && pwd)"
: "${JAVA_HOME:=/usr/lib/jvm/java-17-openjdk}"
export PATH="$JAVA_HOME/bin:$PATH"
: "${SERIAL:=192.168.240.112:5555}"
: "${CL_DEX:?set CL_DEX to a dex/jar containing org/npci/upi/security (e.g. an app classesN.dex)}"

CACHE="$HERE/.cache"
mkdir -p "$CACHE"
R8="$CACHE/r8.jar"
[[ -f "$R8" ]] || curl -sSL -o "$R8" "https://maven.google.com/com/android/tools/r8/8.3.37/r8-8.3.37.jar"

# 1. States + session key + expected decisions (host side, from the C wallet).
make -C "$LITE" waydroid-gen >/dev/null
"$LITE/build/gen_waydroid_states" "$CACHE"

# 2. Build the harness dex and bundle the test signer cert as the signer-upi.crt resource.
javac -d "$CACHE/classes" "$HERE/CLHarness.java"
java -cp "$R8" com.android.tools.r8.D8 --min-api 30 --output "$CACHE" "$CACHE/classes/CLHarness.class"
cp "$CACHE/cert.pem" "$CACHE/signer-upi.crt"
( cd "$CACHE" && zip -q -j harness.jar classes.dex signer-upi.crt )

# 3. Push the harness and the genuine CL dex to the device.
adb -s "$SERIAL" shell 'rm -rf /data/local/tmp/lx; mkdir -p /data/local/tmp/lx'
adb -s "$SERIAL" push "$CACHE/harness.jar" /data/local/tmp/lx/harness.jar >/dev/null
# CL_DEX is the app APK (all dexes; R8 scattered the CL's helper classes across them). harness.jar
# precedes it so our test signer-upi.crt wins over the app's real one for riskRules verify.
adb -s "$SERIAL" push "$CL_DEX" /data/local/tmp/lx/cl.apk >/dev/null

# 4. Run the genuine sync per case and compare to the expected device result.
CP=/data/local/tmp/lx/harness.jar:/data/local/tmp/lx/cl.apk
fail=0
while IFS=$'\t' read -r label mob dev acc k old new cdec expect; do
    # Fresh account ref per case → fresh alias → fresh vault + keystore keys (acc is not in the signed state).
    acc="ACC$(date +%s%N)"
    # </dev/null so adb shell does not swallow the loop's stdin; 240s covers first-run APK verification.
    out=$(timeout 240 adb -s "$SERIAL" shell "CLASSPATH=$CP app_process /system/bin CLHarness $mob $dev $acc $k $old $new $label" </dev/null 2>&1 | tr -d '\r')
    got=$(printf '%s\n' "$out" | sed -n 's/^RESULT '"$label"' //p')
    if [[ "$got" == "$expect" ]]; then
        echo "PASS $label: genuine CL=$got  (C=$cdec)"
    else
        fail=1
        echo "FAIL $label: genuine CL=[$got] expected=$expect  (C=$cdec)"
        printf '%s\n' "$out" | sed 's/^/    /'
    fi
done < "$CACHE/cases.tsv"

echo "waydroid genuine-sync: $([[ $fail == 0 ]] && echo PASS || echo FAIL)"
exit $fail

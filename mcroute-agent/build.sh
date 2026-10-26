#!/bin/bash
# Builds macdpi-mcroute.jar - a self-contained java agent (ByteBuddy shaded in).
# Needs a JDK (17+) on PATH or at JAVA_HOME. No Gradle, no Minecraft mappings.
set -euo pipefail
cd "$(dirname "$0")"

BB_VER=1.18.16-jdk5
if [ ! -f lib/byte-buddy.jar ]; then
  echo "fetching ByteBuddy $BB_VER"
  mkdir -p lib
  curl -fsSL -o lib/byte-buddy.jar \
    "https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy/$BB_VER/byte-buddy-$BB_VER.jar" \
    || { echo "could not download ByteBuddy; place byte-buddy jar at lib/byte-buddy.jar"; exit 1; }
fi

JAVAC="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
JAR="${JAVA_HOME:+$JAVA_HOME/bin/}jar"
OUT="build/macdpi-mcroute.jar"

rm -rf build/classes && mkdir -p build/classes

echo "compiling"
"$JAVAC" -source 17 -target 17 -cp lib/byte-buddy.jar \
    -d build/classes $(find src -name '*.java')

echo "shading ByteBuddy"
# Only its classes (net/), not its manifest or module-info, so our manifest wins.
( cd build/classes && unzip -oq ../../lib/byte-buddy.jar 'net/*' )

echo "writing manifest"
cat > build/MANIFEST.MF <<'EOF'
Manifest-Version: 1.0
Premain-Class: com.macdpi.mcroute.Agent
Agent-Class: com.macdpi.mcroute.Agent
Can-Retransform-Classes: true
Can-Redefine-Classes: true
EOF

echo "packaging $OUT"
"$JAR" cfm "$OUT" build/MANIFEST.MF -C build/classes .
echo "built: $OUT ($(du -h "$OUT" | cut -f1))"

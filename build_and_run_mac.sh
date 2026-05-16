#!/usr/bin/env bash
# Сборка и запуск Phishing URL Detector на macOS
# Использование: bash build_and_run_mac.sh

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=================================================="
echo "  Phishing URL Detector — macOS build & run"
echo "=================================================="
echo ""

# 1. Проверка Java
echo "[1/4] Проверка Java..."
if ! command -v java >/dev/null 2>&1; then
    echo "  [!] Java не найдена."
    echo "      Установи: brew install --cask temurin@17"
    exit 1
fi

JAVA_VER=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+)\..*"/\1/' | head -1)
# fallback parsing
JAVA_FULL=$(java -version 2>&1 | head -1)
echo "      $JAVA_FULL"

JAVA_MAJOR=$(java -version 2>&1 | head -1 | grep -oE '"[0-9]+' | head -1 | tr -d '"')
if [ -z "$JAVA_MAJOR" ] || [ "$JAVA_MAJOR" -lt 17 ]; then
    echo "  [!] Нужна Java 17+ (сейчас: $JAVA_MAJOR)."
    echo "      Установи: brew install --cask temurin@17"
    echo "      Или: brew install openjdk@17 && echo 'export PATH=\"/opt/homebrew/opt/openjdk@17/bin:\$PATH\"' >> ~/.zshrc"
    exit 1
fi
echo "      OK"
echo ""

# 2. Проверка Maven
echo "[2/4] Проверка Maven..."
if ! command -v mvn >/dev/null 2>&1; then
    echo "  [!] Maven не найден."
    echo "      Установи: brew install maven"
    echo ""
    echo "  Если Maven не нужен (только запуск), можно сразу запустить уже собранный JAR:"
    echo "      java -jar target/phishing-url-detector.jar --web 8080"
    exit 1
fi
mvn -version | head -1
echo "      OK"
echo ""

# 3. Сборка
echo "[3/4] mvn clean package -DskipTests ..."
mvn clean package -DskipTests -q
echo "      JAR: $(ls -lh target/phishing-url-detector.jar | awk '{print $5}')"
echo ""

# 4. Запуск web-сервера
echo "[4/4] Запуск web-сервера на http://localhost:8080/ ..."
echo "      (Ctrl+C для остановки)"
echo ""
java -jar target/phishing-url-detector.jar --web 8080

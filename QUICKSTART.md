# ⚡ QUICKSTART

> Get from zero to running ML results in under 30 minutes.

## Prerequisites

- **JDK 17+** — check with `java -version`
- **Maven 3.9+** — check with `mvn -v`
- **git**
- **curl** or PowerShell (to download the dataset)

No JDK? Grab [Adoptium Temurin 17](https://adoptium.net/).

## Steps

### 1. Download the dataset (~1 min)

macOS / Linux / Git Bash:
```bash
curl -L \
  "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff" \
  -o data/PhishingData.arff
```

PowerShell:
```powershell
Invoke-WebRequest `
  "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff" `
  -OutFile data/PhishingData.arff
```

> **Note:** the dataset is already included in this repo at `data/PhishingData.arff` — skip this step if it's there.

### 2. Build (~3–5 min, first run downloads Weka from Maven Central)

```bash
mvn clean package
```

Output: `target/phishing-url-detector.jar` (fat-jar, ~30 MB).

### 3. Run

```bash
java -jar target/phishing-url-detector.jar
```

Expected output — metrics table and confusion matrices printed to console, results saved to `docs/results/metrics.csv`.

### 4. Run unit tests

```bash
mvn test
```

All tests should pass (green).

### 5. Start the web interface (optional)

```bash
java -jar target/phishing-url-detector.jar --web
```

Open [http://localhost:8080](http://localhost:8080) to check URLs interactively.

## Troubleshooting

| Problem | Fix |
|---|---|
| `mvn` not found | Download [Maven](https://maven.apache.org/download.cgi), unpack, add to PATH |
| `Unsupported class file major version 61` | Upgrade to JDK 17+, check `java -version` |
| `Cannot find PhishingData.arff` | Run step 1 to download the dataset |
| `OutOfMemoryError` | `java -Xmx2g -jar target/phishing-url-detector.jar` |
| Weka download fails | Check your internet connection; if behind a corporate proxy, configure `~/.m2/settings.xml` |

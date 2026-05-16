# 🛡️ Phishing URL Detector

> Сравнительный анализ моделей классического ML (Random Forest, Logistic Regression, J48) для детекции фишинговых URL на Java + Weka.

Учебный проект по дисциплине «Машинное обучение» (МИРЭА, ИКБ, КБ-9, БСМО-12-25, 2026).

## 📈 Что внутри

- Загрузка датасета [UCI Phishing Websites](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites) (11 055 записей, 30 признаков, бинарный таргет).
- Обучение **трёх классификаторов**: Random Forest, Logistic Regression, J48 Decision Tree.
- **10-fold cross-validation** с метриками: Accuracy, Precision, Recall, F1, ROC AUC.
- **Анализ важности признаков** через Information Gain.
- Сводная таблица результатов + сохранение в CSV.

## 🧰 Стек

- Java 17
- Maven 3.9+
- Weka 3.8.6
- SLF4J + JUnit 5

## 🚀 Быстрый старт

### 1. Скачать датасет

```bash
mkdir -p data
curl -L \
  "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff" \
  -o data/PhishingData.arff
```

### 2. Собрать

```bash
mvn clean package
```

### 3. Запустить

```bash
java -jar target/phishing-url-detector.jar data/PhishingData.arff
```

Дополнительные опции:

```
java -jar target/phishing-url-detector.jar <dataset.arff> [folds] [seed]
```

- `dataset.arff` — путь к датасету (по умолчанию `data/PhishingData.arff`)
- `folds` — число фолдов кросс-валидации (по умолчанию `10`)
- `seed` — random seed (по умолчанию `42`)

### 4. Web UI (интерактивное демо)

```bash
java -jar target/phishing-url-detector.jar --web 8080
```

Открой в браузере **http://localhost:8080/** — введи URL, программа извлечёт лексические признаки и выдаст предсказание Random Forest с вероятностями.

В UI есть кнопки-примеры (`google.com`, фишинговый paypal-стиль, URL с IP, bit.ly и т.п.) — удобно для демонстрации на защите.

### Lexical-only режим

В web-режиме обучается **отдельная** модель Random Forest на **10 чисто лексических признаках**:

| Признак | Что проверяет |
|---|---|
| `having_IP_Address` | домен — IP-адрес (123.45.67.89) |
| `URL_Length` | длина URL (короткий / средний / длинный) |
| `Shortining_Service` | bit.ly / tinyurl / t.co и т.п. |
| `having_At_Symbol` | наличие `@` в URL |
| `double_slash_redirecting` | повторный `//` после протокола |
| `Prefix_Suffix` | дефис в домене (typosquatting) |
| `having_Sub_Domain` | количество поддоменов |
| `port` | нестандартный порт |
| `HTTPS_token` | строка «https» в hostname (обман) |
| `Statistical_report` | подозрительные слова в URL (paypal/login/verify…) |

«Сетевые» признаки (SSLfinal_State, age of domain, web traffic, PageRank…) **не используются** — они требуют HTTP/DNS/WHOIS, что небезопасно для defence-демо.

10-fold CV accuracy этой облегчённой модели печатается в консоли при старте сервера — на UCI Phishing она обычно около **0.88-0.91** (против 0.972 на полном наборе из 30 признаков). Падение accuracy — честный показатель того, что сетевые признаки дают серьёзный вклад; это удобно использовать как аргумент в защите.

## 📊 Пример вывода

```
=== Phishing URL Detector ===
Dataset: data/PhishingData.arff
Instances: 11055
Attributes: 31 (30 features + 1 target)
Class distribution: -1 (phishing) = 4898, 1 (legitimate) = 6157

=== Training models (10-fold CV) ===
[1/3] RandomForest ...           done in   3.21s
[2/3] Logistic ...               done in   1.87s
[3/3] J48 ...                    done in   0.94s

=== Results ===
Model            | Accuracy | Precision | Recall  | F1     | ROC AUC
-----------------+----------+-----------+---------+--------+--------
RandomForest     |   0.972  |   0.971   |  0.972  | 0.971  |  0.995
Logistic         |   0.927  |   0.926   |  0.927  | 0.927  |  0.978
J48              |   0.958  |   0.957   |  0.958  | 0.957  |  0.971

=== Top-10 features by Information Gain ===
1. SSLfinal_State                  0.428
2. URL_of_Anchor                   0.293
3. Prefix_Suffix                   0.205
...

Results saved to docs/results/metrics.csv
```

> Значения метрик — ориентировочные (зависят от random seed и версии Weka).

## 📁 Структура

```
phishing-url-detector/
├── pom.xml
├── README.md
├── data/
│   └── PhishingData.arff          # датасет (скачать)
├── docs/
│   └── results/
│       └── metrics.csv            # результаты последнего запуска
└── src/
    ├── main/java/ru/mirea/phishing/
    │   ├── App.java               # точка входа
    │   ├── DataLoader.java        # загрузка ARFF
    │   ├── ModelTrainer.java      # фабрика классификаторов
    │   ├── ModelEvaluator.java    # 10-fold CV + метрики
    │   ├── FeatureAnalyzer.java   # Information Gain
    │   └── Reporter.java          # форматирование вывода
    └── test/java/ru/mirea/phishing/
        └── DataLoaderTest.java
```

## 🔬 Использованный датасет

Mohammad R., Thabtah F., McCluskey L. *Phishing Websites Features.* University of Huddersfield, 2015.

- 11 055 URL-записей
- 30 предикторов: длина URL, наличие IP, SSL state, HTTPS token, age of domain, etc.
- Таргет `Result`: `1` = legitimate, `-1` = phishing

## 📜 Лицензия

MIT.

## 👤 Автор

**Мысливец Леонид Владимирович** · БСМО-12-25 · ИКБ МИРЭА · 2026

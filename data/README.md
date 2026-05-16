# 📦 Датасет

Здесь должен лежать файл `PhishingData.arff` — датасет [UCI Phishing Websites](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites).

## Скачать

```bash
curl -L \
  "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff" \
  -o data/PhishingData.arff
```

Или через PowerShell:

```powershell
Invoke-WebRequest `
  "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff" `
  -OutFile data/PhishingData.arff
```

## Краткое описание

- **Размер:** 11 055 записей
- **Признаков:** 30
- **Таргет:** `Result` ∈ {-1, 1}
  - `-1` — фишинговый URL
  - `1` — легитимный URL

## Источник

Mohammad, R. M., Thabtah, F., & McCluskey, L. (2015). *Phishing Websites Features.* University of Huddersfield.

[UCI page →](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites)

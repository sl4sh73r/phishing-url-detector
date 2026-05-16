package ru.mirea.phishing;

import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;

import java.nio.file.Path;
import java.util.Random;

/**
 * Прогревает Random Forest при старте, держит модель в памяти и предсказывает по URL.
 * <p>
 * В режиме {@code lexicalOnly=true} обучает модель на подмножестве признаков,
 * которое реально можно извлечь из строки URL (см. {@link LexicalModelTrainer}).
 */
public final class PredictionService {

    private final Classifier model;
    private final Instances datasetSchema;
    private final double accuracy;     // 10-fold CV accuracy текущей модели
    private final int featureCount;

    private PredictionService(Classifier model, Instances datasetSchema,
                              double accuracy, int featureCount) {
        this.model = model;
        this.datasetSchema = datasetSchema;
        this.accuracy = accuracy;
        this.featureCount = featureCount;
    }

    public static PredictionService bootstrap(Path datasetPath, long seed, boolean lexicalOnly)
            throws Exception {
        Instances data = DataLoader.load(datasetPath);
        if (lexicalOnly) {
            data = LexicalModelTrainer.toLexicalOnly(data);
        }

        Classifier rf = ModelTrainer.randomForest(seed);

        // Замеряем CV-accuracy на той же выборке (даём пользователю честное число)
        Evaluation eval = new Evaluation(data);
        eval.crossValidateModel(ModelTrainer.randomForest(seed), data, 10, new Random(seed));
        double cv = eval.pctCorrect() / 100.0;

        // А теперь обучаем финальную модель на всех данных
        rf.buildClassifier(data);

        int featureCount = data.numAttributes() - 1; // минус class
        return new PredictionService(rf, data, cv, featureCount);
    }

    public double getAccuracy() { return accuracy; }
    public int getFeatureCount() { return featureCount; }

    public Prediction predict(String url) throws Exception {
        double[] features = UrlFeatureExtractor.extract(url);
        String ruleOverride = checkHardRules(url);

        Instance instance = new DenseInstance(datasetSchema.numAttributes());
        instance.setDataset(datasetSchema);

        // Сопоставляем по имени атрибута (порядок в ARFF может отличаться)
        for (int i = 0; i < UrlFeatureExtractor.FEATURE_NAMES.size(); i++) {
            String featureName = UrlFeatureExtractor.FEATURE_NAMES.get(i);
            Attribute attr = datasetSchema.attribute(featureName);
            if (attr == null) continue;  // нет в схеме — lexical-only mode

            int intValue = (int) features[i];
            String stringVal = String.valueOf(intValue);
            int valueIdx = attr.indexOfValue(stringVal);

            if (valueIdx < 0) {
                // значение «0» отсутствует в атрибуте → помечаем missing
                instance.setMissing(attr);
            } else {
                instance.setValue(attr, valueIdx);
            }
        }
        instance.setClassMissing();

        double[] distribution = model.distributionForInstance(instance);

        int phishingIdx = datasetSchema.classAttribute().indexOfValue("-1");
        int legitIdx = datasetSchema.classAttribute().indexOfValue("1");
        if (phishingIdx < 0) phishingIdx = 0;
        if (legitIdx < 0) legitIdx = 1;

        double probPhishing = distribution[phishingIdx];
        double probLegit = distribution[legitIdx];

        // Rule-based слой: если сработало явное правило (IDN-атака и т.п.),
        // — поднимаем уверенность до 0.95. Это страховка от слабости модели,
        // обученной на UCI 2015 (без IDN-примеров).
        if (ruleOverride != null) {
            probPhishing = Math.max(probPhishing, 0.95);
            probLegit = 1.0 - probPhishing;
        }

        boolean isPhishing = probPhishing > probLegit;
        return new Prediction(url, isPhishing, probPhishing, probLegit, features, ruleOverride);
    }

    /**
     * Жёсткие правила, которые модель может пропустить из-за слабостей
     * обучающей выборки. Возвращает понятное имя сработавшего правила или null.
     */
    private static String checkHardRules(String url) {
        try {
            String normalized = url.startsWith("http") ? url : "http://" + url;
            java.net.URI uri = java.net.URI.create(normalized);
            String host = uri.getHost() == null ? "" : uri.getHost();
            String hostLower = host.toLowerCase();

            // IDN / homograph (кириллица или другой не-латин в домене)
            if (host.chars().anyMatch(c -> c > 127)) {
                return "IDN_NON_ASCII_HOST";
            }
            if (hostLower.contains("xn--")) {
                return "IDN_PUNYCODE_HOST";
            }
            // Freenom / cheap TLD + любой бренд/триггер в домене
            for (String tld : java.util.List.of(".tk", ".cf", ".ml", ".gq", ".ga", ".pw")) {
                if (hostLower.endsWith(tld)) {
                    return "SUSPICIOUS_TLD_" + tld.substring(1).toUpperCase();
                }
            }
        } catch (Exception ignored) {
            // не валидный URL — пускай модель решает
        }
        return null;
    }

    public record Prediction(
            String url,
            boolean phishing,
            double probabilityPhishing,
            double probabilityLegitimate,
            double[] features,
            String ruleOverride // имя сработавшего hard-правила, или null
    ) {}
}

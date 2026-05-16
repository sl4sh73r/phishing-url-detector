package ru.mirea.phishing;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import weka.classifiers.Classifier;
import weka.core.Instances;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Точка входа в Phishing URL Detector.
 * <p>
 * Запуск:
 * <pre>
 *   java -jar phishing-url-detector.jar [dataset.arff] [folds] [seed]
 * </pre>
 */
public final class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    private App() {}

    public static void main(String[] args) throws Exception {
        // --- Web UI mode ---
        // java -jar phishing-url-detector.jar --web [port] [dataset]
        if (args.length > 0 && "--web".equalsIgnoreCase(args[0])) {
            int port = args.length > 1 ? Integer.parseInt(args[1]) : 8080;
            Path datasetPath = Paths.get(args.length > 2 ? args[2] : "data/PhishingData.arff");

            System.out.println("=== Phishing URL Detector · Web UI ===");
            System.out.println("Mode: lexical-only (10 признаков, извлекаемых из URL без сетевых запросов)");
            System.out.println("Загружаем датасет и обучаем Random Forest...");
            long t0 = System.nanoTime();
            PredictionService service = PredictionService.bootstrap(datasetPath, 42L, true);
            System.out.printf("Модель готова за %.2fс · features=%d · 10-fold CV accuracy=%.3f%n",
                    (System.nanoTime() - t0) / 1e9, service.getFeatureCount(), service.getAccuracy());

            WebServer server = new WebServer(service, port);
            server.start();
            System.out.println("Открой в браузере: http://localhost:" + port + "/");
            System.out.println("Для остановки нажми Ctrl+C");
            Thread.currentThread().join(); // блокируем main
            return;
        }

        // --- CV режим по умолчанию (как раньше) ---
        Path dataset = Paths.get(args.length > 0 ? args[0] : "data/PhishingData.arff");
        int folds = args.length > 1 ? Integer.parseInt(args[1]) : 10;
        long seed = args.length > 2 ? Long.parseLong(args[2]) : 42L;

        System.out.println("=== Phishing URL Detector ===");
        System.out.println("Dataset: " + dataset);

        Instances data = DataLoader.load(dataset);
        System.out.printf("Instances: %d%n", data.numInstances());
        System.out.printf("Attributes: %d (%d features + 1 target)%n",
                data.numAttributes(), data.numAttributes() - 1);
        System.out.println("Class: " + data.classAttribute().name());
        System.out.println("Class distribution: " + DataLoader.classDistribution(data));
        System.out.println();

        System.out.printf("=== Training models (%d-fold CV) ===%n", folds);

        Map<String, Classifier> models = ModelTrainer.standardModels(seed);
        Map<String, ModelEvaluator.Result> results = new LinkedHashMap<>();

        int idx = 1;
        for (Map.Entry<String, Classifier> entry : models.entrySet()) {
            String name = entry.getKey();
            Classifier model = entry.getValue();
            long t0 = System.nanoTime();
            ModelEvaluator.Result r = ModelEvaluator.crossValidate(model, data, folds, seed);
            double elapsed = (System.nanoTime() - t0) / 1e9;
            System.out.printf("[%d/%d] %-30s done in %6.2fs%n",
                    idx++, models.size(), name, elapsed);
            results.put(name, r);
        }
        System.out.println();

        Reporter.printResultsTable(results);
        System.out.println();

        System.out.println("=== Top-10 features by Information Gain ===");
        FeatureAnalyzer.topFeaturesByInformationGain(data, 10)
                .forEach((feature, score) ->
                        System.out.printf("  %-32s %.3f%n", feature, score));
        System.out.println();

        Path metricsCsv = Paths.get("docs/results/metrics.csv");
        Reporter.saveAsCsv(results, metricsCsv);
        System.out.println("Results saved to " + metricsCsv);
    }
}

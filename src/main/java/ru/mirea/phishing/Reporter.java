package ru.mirea.phishing;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Форматирует и сохраняет результаты прогона.
 */
public final class Reporter {

    private Reporter() {}

    /**
     * Печатает в консоль красивую таблицу метрик.
     */
    public static void printResultsTable(Map<String, ModelEvaluator.Result> results) {
        System.out.println("=== Results ===");
        System.out.printf("%-16s | %-8s | %-9s | %-7s | %-6s | %-7s%n",
                "Model", "Accuracy", "Precision", "Recall", "F1", "ROC AUC");
        System.out.println("-----------------+----------+-----------+---------+--------+--------");
        for (Map.Entry<String, ModelEvaluator.Result> e : results.entrySet()) {
            ModelEvaluator.Result r = e.getValue();
            System.out.printf("%-16s |   %.3f  |   %.3f   |  %.3f  | %.3f  |  %.3f%n",
                    e.getKey(), r.accuracy(), r.precision(), r.recall(), r.f1(), r.rocAuc());
        }

        System.out.println();
        System.out.println("=== Confusion matrices ===");
        for (Map.Entry<String, ModelEvaluator.Result> e : results.entrySet()) {
            System.out.println("--- " + e.getKey() + " ---");
            System.out.println(e.getValue().confusionMatrix());
        }
    }

    /**
     * Сохраняет таблицу метрик в CSV-файл.
     */
    public static void saveAsCsv(Map<String, ModelEvaluator.Result> results, Path output)
            throws IOException {
        Files.createDirectories(output.getParent());
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(output))) {
            pw.println("model,accuracy,precision,recall,f1,roc_auc");
            for (Map.Entry<String, ModelEvaluator.Result> e : results.entrySet()) {
                ModelEvaluator.Result r = e.getValue();
                pw.printf("%s,%.6f,%.6f,%.6f,%.6f,%.6f%n",
                        e.getKey(), r.accuracy(), r.precision(),
                        r.recall(), r.f1(), r.rocAuc());
            }
        }
    }
}

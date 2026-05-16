package ru.mirea.phishing;

import weka.classifiers.Classifier;
import weka.classifiers.functions.Logistic;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Фабрика классификаторов. Возвращает преднастроенные модели Weka.
 */
public final class ModelTrainer {

    private ModelTrainer() {}

    /**
     * Стандартный набор моделей для сравнения:
     * Random Forest, Logistic Regression, J48 Decision Tree.
     *
     * @param seed random seed для воспроизводимости
     */
    public static Map<String, Classifier> standardModels(long seed) {
        Map<String, Classifier> models = new LinkedHashMap<>();
        models.put("RandomForest", randomForest(seed));
        models.put("Logistic",     logisticRegression());
        models.put("J48",          j48());
        return models;
    }

    public static RandomForest randomForest(long seed) {
        RandomForest rf = new RandomForest();
        rf.setNumIterations(100);            // 100 деревьев
        rf.setSeed((int) seed);
        rf.setNumExecutionSlots(0);          // авто (все ядра)
        return rf;
    }

    public static Logistic logisticRegression() {
        Logistic logistic = new Logistic();
        logistic.setMaxIts(200);             // лимит итераций оптимизации
        return logistic;
    }

    public static J48 j48() {
        J48 j48 = new J48();
        j48.setConfidenceFactor(0.25f);
        j48.setMinNumObj(2);
        return j48;
    }
}

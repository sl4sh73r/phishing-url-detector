package ru.mirea.phishing;

import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.core.Instances;

import java.util.Random;

/**
 * Кросс-валидация и расчёт метрик через {@link Evaluation}.
 */
public final class ModelEvaluator {

    private ModelEvaluator() {}

    /**
     * Иммутабельный результат прогона одной модели.
     */
    public record Result(
            double accuracy,
            double precision,
            double recall,
            double f1,
            double rocAuc,
            String confusionMatrix
    ) {}

    /**
     * Прогоняет k-fold cross-validation и возвращает агрегированные метрики
     * (weighted average по классам).
     */
    public static Result crossValidate(Classifier classifier,
                                       Instances data,
                                       int folds,
                                       long seed) throws Exception {
        Evaluation eval = new Evaluation(data);
        eval.crossValidateModel(classifier, data, folds, new Random(seed));

        return new Result(
                eval.pctCorrect() / 100.0,
                eval.weightedPrecision(),
                eval.weightedRecall(),
                eval.weightedFMeasure(),
                eval.weightedAreaUnderROC(),
                eval.toMatrixString("Confusion matrix")
        );
    }
}

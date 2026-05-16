package ru.mirea.phishing;

import weka.attributeSelection.AttributeSelection;
import weka.attributeSelection.InfoGainAttributeEval;
import weka.attributeSelection.Ranker;
import weka.core.Instances;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Анализ важности признаков через Information Gain.
 */
public final class FeatureAnalyzer {

    private FeatureAnalyzer() {}

    /**
     * Возвращает top-N признаков, отсортированных по убыванию Information Gain.
     *
     * @param data входной датасет (с установленным classIndex)
     * @param n    сколько топ-признаков вернуть
     * @return LinkedHashMap [имя_атрибута → IG], в порядке убывания значимости
     */
    public static Map<String, Double> topFeaturesByInformationGain(Instances data, int n)
            throws Exception {
        AttributeSelection selector = new AttributeSelection();
        InfoGainAttributeEval evaluator = new InfoGainAttributeEval();
        Ranker ranker = new Ranker();
        ranker.setThreshold(-Double.MAX_VALUE);
        ranker.setNumToSelect(-1);

        selector.setEvaluator(evaluator);
        selector.setSearch(ranker);
        selector.SelectAttributes(data);

        // rankedAttributes() → массив [attr_index, score], отсортирован по score desc
        double[][] ranked = selector.rankedAttributes();
        Map<String, Double> top = new LinkedHashMap<>();
        int limit = Math.min(n, ranked.length);
        for (int i = 0; i < limit; i++) {
            int attrIdx = (int) ranked[i][0];
            double score = ranked[i][1];
            top.put(data.attribute(attrIdx).name(), score);
        }
        return top;
    }
}

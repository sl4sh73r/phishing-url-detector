package ru.mirea.phishing;

import weka.core.Attribute;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Подготавливает обрезанный датасет с ТОЛЬКО лексическими признаками
 * (теми, что можно посчитать из строки URL без HTTP/DNS/WHOIS).
 * <p>
 * Используется для web-режима: модель обучается на этом подмножестве
 * и потом делает осмысленные предсказания по live-URL.
 */
public final class LexicalModelTrainer {

    /**
     * Признаки, которые реально можно вычислить из строки URL.
     * Эти 10 фичей покрывают типичные фишинговые паттерны:
     * IP-адрес вместо домена, экстремальная длина, shortener-сервисы,
     * @-символ, двойной слэш-редирект, дефис в домене (typosquatting),
     * лишние поддомены, нестандартный порт, https в hostname (обман),
     * подозрительные слова.
     */
    public static final List<String> LEXICAL_FEATURES = List.of(
            "having_IP_Address",
            "URL_Length",
            "Shortining_Service",
            "having_At_Symbol",
            "double_slash_redirecting",
            "Prefix_Suffix",
            "having_Sub_Domain",
            "port",
            "HTTPS_token",
            "Statistical_report"
    );

    private LexicalModelTrainer() {}

    /**
     * Возвращает копию датасета, в которой оставлены только лексические
     * признаки + class-атрибут. Все остальные удаляются через Weka Remove-filter.
     */
    public static Instances toLexicalOnly(Instances data) throws Exception {
        int classIdx = data.classIndex();
        List<Integer> keep = new ArrayList<>();

        for (String name : LEXICAL_FEATURES) {
            Attribute attr = data.attribute(name);
            if (attr != null) keep.add(attr.index());
        }
        keep.add(classIdx);

        int[] keepArr = keep.stream().mapToInt(Integer::intValue).toArray();
        Arrays.sort(keepArr);

        Remove remove = new Remove();
        remove.setAttributeIndicesArray(keepArr);
        remove.setInvertSelection(true); // оставить указанные, удалить остальные
        remove.setInputFormat(data);
        Instances filtered = Filter.useFilter(data, remove);
        // setInputFormat не всегда сохраняет class index — фиксируем явно
        filtered.setClassIndex(filtered.numAttributes() - 1);
        return filtered;
    }
}

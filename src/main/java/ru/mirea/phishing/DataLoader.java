package ru.mirea.phishing;

import weka.core.Attribute;
import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Загружает датасет в формате Weka ARFF и подготавливает его к обучению.
 */
public final class DataLoader {

    private DataLoader() {}

    /**
     * Загружает датасет и автоматически устанавливает индекс класса (последний атрибут).
     *
     * @param path путь к .arff файлу
     * @return подготовленный Instances
     */
    public static Instances load(Path path) throws Exception {
        if (!Files.exists(path)) {
            throw new IllegalStateException("Dataset not found: " + path.toAbsolutePath()
                    + ". Скачайте его командой: curl -L "
                    + "\"https://archive.ics.uci.edu/ml/machine-learning-databases/00327/"
                    + "Training%20Dataset.arff\" -o " + path);
        }
        DataSource source = new DataSource(path.toAbsolutePath().toString());
        Instances data = source.getDataSet();
        if (data.classIndex() == -1) {
            data.setClassIndex(data.numAttributes() - 1);
        }
        return data;
    }

    /**
     * Возвращает строку с распределением классов в датасете.
     */
    public static String classDistribution(Instances data) {
        Attribute classAttr = data.classAttribute();
        Map<String, Integer> counts = new LinkedHashMap<>();
        Enumeration<Object> values = classAttr.enumerateValues();
        while (values.hasMoreElements()) {
            counts.put(values.nextElement().toString(), 0);
        }
        for (int i = 0; i < data.numInstances(); i++) {
            String label = classAttr.value((int) data.instance(i).classValue());
            counts.merge(label, 1, Integer::sum);
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (!first) sb.append(", ");
            sb.append(e.getKey()).append(" = ").append(e.getValue());
            first = false;
        }
        return sb.toString();
    }
}

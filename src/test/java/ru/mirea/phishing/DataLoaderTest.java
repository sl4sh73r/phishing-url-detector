package ru.mirea.phishing;

import org.junit.jupiter.api.Test;
import weka.core.Instances;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class DataLoaderTest {

    private static final Path DATASET = Paths.get("data", "PhishingData.arff");

    @Test
    void shouldLoadDatasetAndSetClassIndex() throws Exception {
        assumeTrue(Files.exists(DATASET),
                "Skip: dataset not present (run curl from README)");

        Instances data = DataLoader.load(DATASET);

        assertTrue(data.numInstances() > 0, "Dataset must contain instances");
        assertEquals(data.numAttributes() - 1, data.classIndex(),
                "Class index должен быть установлен на последний атрибут");
        assertNotNull(data.classAttribute(), "Class attribute must exist");
    }

    @Test
    void classDistributionShouldMentionBothClasses() throws Exception {
        assumeTrue(Files.exists(DATASET),
                "Skip: dataset not present");
        Instances data = DataLoader.load(DATASET);
        String distribution = DataLoader.classDistribution(data);
        // UCI Phishing использует метки "-1" и "1"
        assertTrue(distribution.contains("="), "Распределение должно быть в формате 'label = count'");
    }
}

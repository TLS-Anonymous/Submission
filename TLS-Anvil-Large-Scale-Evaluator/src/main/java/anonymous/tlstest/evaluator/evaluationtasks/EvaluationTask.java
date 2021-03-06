/**
 * TLS-Testsuite-Large-Scale-Evaluator - A tool for executing the TLS-Testsuite against multiple targets running in Docker containers in parallel
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.evaluator.evaluationtasks;

import anonymous.tlstest.evaluator.DockerCleanupService;
import anonymous.tlstest.evaluator.ProgressTracker;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.model.Image;
import anonymous.tls.subject.TlsImplementationType;
import anonymous.tls.subject.constants.TlsImageLabels;
import anonymous.tls.subject.docker.DockerClientManager;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

abstract public class EvaluationTask implements Runnable {

    protected static final Logger LOGGER = LogManager.getLogger();
    protected static final DockerClient DOCKER = DockerClientManager.getDockerClient();
    private static final int RANDOM_LENGTH = 5;

    protected Image image;
    protected String imageName;
    protected String hostName;
    protected String imageVersion;
    protected TlsImplementationType imageImplementation;

    protected DockerCleanupService cleanupService = new DockerCleanupService();
    protected boolean finished = false;

    abstract public int execute() throws Exception;

    public void run() {
        int exitCode = -1;
        try {
            exitCode = this.execute();
        } catch (Exception e) {
            LOGGER.error("Could not execute task:", e);
        }

        finished = true;
        ProgressTracker.getInstance().taskFinished(this, exitCode);
        cleanupService.cleanup();
    }

    public void setImageToEvaluate(Image image) {
        this.image = image;
        Map<String, String> labels = image.getLabels();
        imageVersion = labels.get(TlsImageLabels.VERSION.getLabelName());
        String implementation = labels.get(TlsImageLabels.IMPLEMENTATION.getLabelName());

        imageName = String.format("%s-%s-%s-%s",
                implementation,
                labels.get(TlsImageLabels.CONNECTION_ROLE.getLabelName()),
                imageVersion,
                RandomStringUtils.randomAlphanumeric(RANDOM_LENGTH)
        );
        hostName = imageName.replace(".", "").replace("_", "-");

        imageImplementation = TlsImplementationType.fromString(implementation);
        if (imageImplementation == null) {
            LOGGER.error("Unknown implementation type!");
            throw new RuntimeException("Unknown implementation type!");
        }
    }

    public String getImageName() {
        return imageName;
    }

    public void waitForContainerToFinish(String id) {
        boolean finished = false;
        int waitCounter = 0;
        while (!finished) {
            try {
                boolean isRunning = DOCKER.inspectContainerCmd(id).exec().getState().getRunning();
                finished = !isRunning;
                Thread.sleep(5000);
                waitCounter++;
                if (waitCounter % 6 == 0) {
                    waitCounter = 0;
                    LOGGER.debug("Still waiting for " + getUnRandomizedImageName() + " to finish... (" + id + ")");
                }
            } catch (InterruptedException ignored) {
            } catch (Exception e) {
                LOGGER.warn("DOCKER error...", e);
            }
        }

        LOGGER.debug("Waiting finished for " + getUnRandomizedImageName() + " finished (" + id + ")");
    }

    public String getUnRandomizedImageName() {
        return imageName.substring(0, imageName.length() - RANDOM_LENGTH - 1);
    }
}

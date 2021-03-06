/**
 * TLS-Testsuite-Large-Scale-Evaluator - A tool for executing the TLS-Testsuite against multiple targets running in Docker containers in parallel
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.evaluator;

import anonymous.tlstest.evaluator.constants.ImplementationModeType;
import anonymous.tlstest.evaluator.evaluationtasks.EvaluationTaskFactory;
import com.github.dockerjava.api.model.Image;
import anonymous.tlstest.evaluator.evaluationtasks.EvaluationTask;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class Evaluator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final List<Image> clientImages;
    private final List<Image> serverImages;
    private final ThreadPoolExecutor executor;

    public Evaluator(List<Image> clientImages, List<Image> serverImages) {
        this.clientImages = clientImages;
        this.serverImages = serverImages;

        int size = Config.getInstance().getParallel();
        this.executor = new ThreadPoolExecutor(size, size, 10, TimeUnit.DAYS, new LinkedBlockingDeque<Runnable>());
    }

    private void submit(List<Future<?>> futures, EvaluationTask task) {
        if (futures.size() > 0 && !Config.getInstance().isNoRampUpTime()) {
            try {
                Thread.sleep(80 * 1000);
            } catch (Exception ignored) {
            }
        }

        futures.add(executor.submit(task));
    }


    public void start() {
        List<Future<?>> futures = new ArrayList<>();

        ProgressTracker.getInstance().setTotalTasks(clientImages.size() + serverImages.size());
        LOGGER.info(String.format("Starting %d tasks", ProgressTracker.getInstance().getTotalTasks()));

        for (Image image : clientImages) {
            EvaluationTask task = EvaluationTaskFactory.forMode(ImplementationModeType.CLIENT);
            task.setImageToEvaluate(image);
            LOGGER.debug("Schedule test for image " + image.getRepoTags()[0]);
            submit(futures, task);
        }

        for (Image image : serverImages) {
            EvaluationTask task = EvaluationTaskFactory.forMode(ImplementationModeType.SERVER);
            task.setImageToEvaluate(image);
            LOGGER.debug("Schedule test for image " + image.getRepoTags()[0]);
            submit(futures, task);
        }


        for (Future<?> i : futures) {
            try {
                i.get();
            } catch (Exception e) {
                LOGGER.error(e);
            }
        }

        LOGGER.info("Evaluator finished");
        executor.shutdownNow();
        ProgressTracker.getInstance().createReport();
        System.exit(0);
    }
}

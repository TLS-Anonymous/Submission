/**
 * TLS-Testsuite-Large-Scale-Evaluator - A tool for executing the TLS-Testsuite against multiple targets running in Docker containers in parallel
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.evaluator.evaluationtasks;

import anonymous.tlstest.evaluator.Config;
import anonymous.tlstest.evaluator.constants.DockerEntity;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Volume;
import anonymous.tls.subject.TlsImplementationType;
import anonymous.tls.subject.docker.DockerTlsClientInstance;
import anonymous.tls.subject.docker.DockerTlsInstance;
import anonymous.tls.subject.docker.DockerTlsManagerFactory;

import java.nio.file.FileSystems;

public class TestsuiteClientEvaluationTask extends EvaluationTask {
    private String networkId;
    private String targetHostname;

    private String createNetwork(String networkName) throws Exception {
        return DOCKER.createNetworkCmd()
                .withAttachable(true)
                .withName(networkName)
                .exec().getId();
    }

    private String createTestsuiteContainer() throws Exception {
        String mountPath = FileSystems.getDefault().getPath(Config.getInstance().getOutputFolder() + "/" + imageName).toString();
        Volume volume = new Volume("/output");
        return DOCKER.createContainerCmd(Config.getInstance().getTestsuiteImage())
                .withName("Testsuite-" + hostName)
                .withEnv("LogFilename=" + imageName)
                .withCmd("-outputFolder", "./",
                        "-parallelHandshakes", "3",
                        "-parallelTests", "3",
                        "-strength", Integer.toString(Config.getInstance().getStrength()),
                        "client",
                        "-port", "443",
                        "-triggerScript", "curl", "--connect-timeout", "2", targetHostname + ":8090/trigger")
                .withHostConfig(HostConfig.newHostConfig()
                        .withNetworkMode(networkId)
                        .withBinds(new Bind(mountPath, volume))
                        .withMemory(Config.getInstance().getContainerRAM() * 1000 * 1000 * 1000L)
                )
                .exec().getId();
    }

    private DockerTlsInstance createTargetContainer(String ipAddress, String testsuiteContainerId) {
        String connectAddressToUse = ipAddress;
        if(imageImplementation == TlsImplementationType.TLSLITE_NG || imageImplementation == TlsImplementationType.RUSTLS) {
            connectAddressToUse = testsuiteContainerId.substring(0, 12);
        }
        DockerTlsClientInstance dockerClientInstance = null;
        try {
            dockerClientInstance = DockerTlsManagerFactory.getTlsClientBuilder(imageImplementation, imageVersion)
                    .ip(connectAddressToUse)
                    .port(443)
                    .insecureConnection(true)
                    .hostname(targetHostname)
                    .hostConfigHook(hostConfig -> {
                        hostConfig
                                .withExtraHosts()
                                .withNetworkMode(networkId);
                        
                        return hostConfig;
                    }).build();
            dockerClientInstance.ensureContainerExists();
        } catch (DockerException | InterruptedException ex) {
            LOGGER.error(ex);
        }
        return dockerClientInstance;
    }

    @Override
    public int execute() throws Exception {
        targetHostname = "target-" + hostName;
        String networkName = imageName + "_network";

        networkId = createNetwork(networkName);
        cleanupService.addEntityToCleanUp(DockerEntity.NETWORK, networkId);

        String testsuiteContainerId = createTestsuiteContainer();
        cleanupService.addEntityToCleanUp(DockerEntity.CONTAINER, testsuiteContainerId);
        DOCKER.startContainerCmd(testsuiteContainerId).exec();
        LOGGER.debug("Testsuite_" + imageName + " container started!");

        String testsuiteIp = DOCKER.inspectContainerCmd(testsuiteContainerId).exec().getNetworkSettings().getNetworks().get(networkName).getIpAddress();
        DockerTlsInstance targetInstance = createTargetContainer(testsuiteIp, testsuiteContainerId);
        cleanupService.addEntityToCleanUp(DockerEntity.CONTAINER, targetInstance.getId());
        targetInstance.start();

        LOGGER.info("Waiting for testsuite " + imageName + " to finish");
        new Thread(() -> {
            while (!finished) {
                LOGGER.debug("Still waiting for container " + getUnRandomizedImageName() + "(" + testsuiteContainerId + ")");
                try {
                    Thread.sleep(30000);
                } catch (Exception e) {}
            }
        }).start();

        int exitCode = DOCKER.waitContainerCmd(testsuiteContainerId).exec(new WaitContainerResultCallback()).awaitStatusCode();
        LOGGER.info("Testsuite for " + imageName + " finished and exited with status code " + exitCode);
        return exitCode;
    }
}

/**
 * TLS-Testsuite-Large-Scale-Evaluator - A tool for executing the TLS-Testsuite against multiple targets running in Docker containers in parallel
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.evaluator;

import com.github.dockerjava.api.DockerClient;
import anonymous.tls.subject.docker.DockerClientManager;
import anonymous.tlstest.evaluator.constants.DockerEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DockerCleanupService {
    protected static final Logger LOGGER = LogManager.getLogger();
    protected static final DockerClient DOCKER = DockerClientManager.getDockerClient();

    private final List<EntityHolder> entitiesToCleanUp = new ArrayList<>();

    public void addEntityToCleanUp(DockerEntity entity, String id) {
        entitiesToCleanUp.add(new EntityHolder(id, entity));
    }

    public void cleanup() {
        Collections.reverse(entitiesToCleanUp);

        entitiesToCleanUp.forEach(i -> {
            try {
                switch (i.entity) {
                    case IMAGE:
                        DOCKER.removeImageCmd(i.entityId).withForce(true).withNoPrune(false).exec();
                        break;
                    case NETWORK:
                        DOCKER.removeNetworkCmd(i.entityId).exec();
                        break;
                    case CONTAINER:
                        DOCKER.removeContainerCmd(i.entityId).withForce(true).exec();
                        break;
                }
            } catch (Exception e) {
                LOGGER.error(e);
            }
        });
    }


    static class EntityHolder {
        private final DockerEntity entity;
        private final String entityId;

        EntityHolder(String id, DockerEntity entity) {
            this.entityId = id;
            this.entity = entity;
        }
    }
}

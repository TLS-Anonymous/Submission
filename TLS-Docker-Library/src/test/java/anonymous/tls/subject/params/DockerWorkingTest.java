package anonymous.tls.subject.params;

import static org.junit.Assert.assertTrue;

import com.github.dockerjava.api.DockerClient;

import org.junit.Test;

import anonymous.tls.subject.docker.DockerClientManager;

public class DockerWorkingTest {
    @Test
    public void isDockerOK() {
        DockerClient docker = DockerClientManager.getDockerClient();
        docker.pingCmd().exec();
        assertTrue(true); // assert that no exception occured
    }
}
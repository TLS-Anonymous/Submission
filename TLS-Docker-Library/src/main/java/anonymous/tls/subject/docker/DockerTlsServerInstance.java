package anonymous.tls.subject.docker;

import java.util.function.UnaryOperator;

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports.Binding;

import anonymous.tls.subject.ConnectionRole;
import anonymous.tls.subject.HostInfo;
import anonymous.tls.subject.params.ParameterProfile;
import anonymous.tls.subject.properties.ImageProperties;
import static java.lang.Thread.sleep;

public class DockerTlsServerInstance extends DockerTlsInstance {

    private int port;
    private final HostInfo hostInfo;
    private final String additionalParameters;
    private final boolean parallelize;
    private final boolean insecureConnection;

    public DockerTlsServerInstance(String containerName, ParameterProfile profile, ImageProperties imageProperties, String version, boolean autoRemove, HostInfo hostInfo, String additionalParameters, boolean parallelize,
            boolean insecureConnection,
            UnaryOperator<HostConfig> hostConfigHook) {
        super(containerName, profile, imageProperties, version, ConnectionRole.SERVER, autoRemove, hostConfigHook);
        this.port = hostInfo.getPort(); // fill with default port
        this.hostInfo = hostInfo;
        this.additionalParameters = additionalParameters;
        this.parallelize = parallelize;
        this.insecureConnection = insecureConnection;
    }

    @Override
    protected HostConfig prepareHostConfig(HostConfig cfg) {
        return super.prepareHostConfig(cfg)
                .withPortBindings(new PortBinding(Binding.empty(), new ExposedPort(imageProperties.getInternalPort(), hostInfo.getType().toInternetProtocol())))
                .withReadonlyRootfs(true);
    }

    @Override
    protected CreateContainerCmd prepareCreateContainerCmd(CreateContainerCmd cmd) {
        String host;
        if (hostInfo.getHostname() == null || imageProperties.isUseIP()) {
            host = hostInfo.getIp();
        } else {
            host = hostInfo.getHostname();
        }
        return super.prepareCreateContainerCmd(cmd)
                .withCmd(parameterProfile.toParameters(host, imageProperties.getInternalPort(), imageProperties, additionalParameters, parallelize, insecureConnection))
                .withExposedPorts(new ExposedPort(imageProperties.getInternalPort(), hostInfo.getType().toInternetProtocol()));
    }

    @Override
    public void start() {
        super.start();
        updateInstancePort();
    }

    /**
     * Update port to match actually exposed port.
     */
    public void updateInstancePort() {
        port = imageProperties.getInternalPort();
    }

    public int getPort() {
        return port;
    }

    public HostInfo getHostInfo() {
        return hostInfo;
    }
}
package anonymous.tls.subject.params;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.util.List;

import javax.xml.bind.JAXBException;

import anonymous.tls.subject.ConnectionRole;
import anonymous.tls.subject.TlsImplementationType;
import anonymous.tls.subject.docker.DockerTlsManagerFactory;
import anonymous.tls.subject.docker.DockerTlsServerInstance;
import anonymous.tls.subject.report.ContainerReport;
import anonymous.tls.subject.report.InstanceContainer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.Test;

public class AvailableServerVersionsTest {

    private Logger LOGGER = LogManager.getLogger();

    public AvailableServerVersionsTest() {
    }

    @Test
    public void listAllServers() {
        for (TlsImplementationType type : TlsImplementationType.values()) {
            List<String> availableVersions = DockerTlsManagerFactory.getAvailableVersions(ConnectionRole.SERVER, type);
            System.out.println("Server version: " + type);
            for (String version : availableVersions) {
                System.out.println(version);
            }
        }
    }

    @Test
    public void testAllVersionsFunctional() throws JAXBException, IOException {
        Configurator.setRootLevel(org.apache.logging.log4j.Level.OFF);
        ContainerReport report = new ContainerReport();
        for (TlsImplementationType type : TlsImplementationType.values()) {
            List<String> availableVersions = DockerTlsManagerFactory.getAvailableVersions(ConnectionRole.SERVER, type);
            for (String version : availableVersions) {
                try {
                    boolean isFunctional = isFunctional(type, version);
                    System.out.println(type.name() + ":" + version + " - " + isFunctional);
                    report.addInstanceContainer(new InstanceContainer(ConnectionRole.SERVER, type, version, isFunctional));
                } catch (Exception E) {
                    E.printStackTrace();
                    System.out.println(type.name() + ":" + version + "       ERROR");
                }

            }
        }
        ContainerReport.write(new File("server_report.xml"), report);
    }

    public boolean isFunctional(TlsImplementationType type, String version) {
        DockerTlsServerInstance server = null;
        try {
            if (version == null || type == null) {
                System.out.println("Null: " + version);
                return false;
            }
            try {
                server = DockerTlsManagerFactory.getTlsServerBuilder(type, version).build();
                server.start();
            } catch (Exception E) {
                LOGGER.warn("Instance seems not runnable", E);
                return false;
            }
            // the hostname part might need some fixing.
            // On windows(wsl2) I needed the IP of the wsl vm here
            Socket socket = new Socket(server.getHostInfo().getHostname(), server.getPort());
            if (socket.isConnected()) {
                return true;
            } else {
                return false;
            }
        } catch (IOException ex) {
            return false;
        } finally {
            if (server != null) {
                server.close();
            }
        }
    }
}

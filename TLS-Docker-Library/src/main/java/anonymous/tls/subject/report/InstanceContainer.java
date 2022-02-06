/*
 */
package anonymous.tls.subject.report;

import anonymous.tls.subject.ConnectionRole;
import anonymous.tls.subject.TlsImplementationType;

import java.io.Serializable;

/**
 *
 * 
 */
public class InstanceContainer implements Serializable {

    private ConnectionRole role;

    private TlsImplementationType implementationType;

    private String version;

    private boolean functional;

    private InstanceContainer() {
    }

    public InstanceContainer(ConnectionRole role, TlsImplementationType implementationType, String version, boolean functional) {
        this.role = role;
        this.implementationType = implementationType;
        this.version = version;
        this.functional = functional;
    }

    public ConnectionRole getRole() {
        return role;
    }

    public void setRole(ConnectionRole role) {
        this.role = role;
    }

    public TlsImplementationType getImplementationType() {
        return implementationType;
    }

    public void setImplementationType(TlsImplementationType implementationType) {
        this.implementationType = implementationType;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public boolean isFunctional() {
        return functional;
    }

    public void setFunctional(boolean functional) {
        this.functional = functional;
    }
}

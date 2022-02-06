/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package anonymous.tls.subject.constants;

import com.github.dockerjava.api.model.InternetProtocol;

/**
 *
 * 
 */
public enum TransportType {
    UDP,
    TCP;

    public InternetProtocol toInternetProtocol() {
        switch (this) {
            case UDP:
                return InternetProtocol.UDP;
            case TCP:
                return InternetProtocol.TCP;
        }
        return null;
    }
}

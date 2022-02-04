/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;

public class TestExtractorDelegate {
    @Parameter(names = "-outputFolder", description = "Folder to output annotated RFC HTML files")
    private String outputFolder = "./";

    @Parameter(names = "-detailed", description = "Print more detailed test information")
    private boolean detailed = false;
    
    public String getOutputFolder() {
        return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolder = outputFolder;
    }

    public boolean isDetailed() {
        return detailed;
    }

    public void setDetailed(boolean detailed) {
        this.detailed = detailed;
    }
}

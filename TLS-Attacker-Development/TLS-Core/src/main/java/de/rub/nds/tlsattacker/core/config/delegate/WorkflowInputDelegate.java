/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import java.io.FileInputStream;

public class WorkflowInputDelegate extends Delegate {

    @Parameter(names = "-workflow_input",
        description = "This parameter allows you to load the whole workflow trace from the specified XML configuration file")
    private String workflowInput = null;

    public WorkflowInputDelegate() {
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    @Override
    public void applyDelegate(Config config) {
        FileInputStream fis = null;
        if (workflowInput != null) {
            config.setWorkflowInput(workflowInput);
        }
    }
}

/**
 * TLS-Testsuite-Large-Scale-Evaluator - A tool for executing the TLS-Testsuite against multiple targets running in Docker containers in parallel
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.evaluator.reporting;

public class EvaluationResult {
    private String imageName;
    private int exitCode;

    private EvaluationResult() {

    }

    public EvaluationResult(String imageName, int exitCode) {
        this.imageName = imageName;
        this.exitCode = exitCode;
    }

    public int getExitCode() {
        return exitCode;
    }

    public String getImageName() {
        return imageName;
    }
}

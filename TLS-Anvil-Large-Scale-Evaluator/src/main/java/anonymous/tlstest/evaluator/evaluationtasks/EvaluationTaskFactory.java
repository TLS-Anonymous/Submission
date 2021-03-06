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
import anonymous.tlstest.evaluator.constants.EvaluationTaskType;
import anonymous.tlstest.evaluator.constants.ImplementationModeType;

public class EvaluationTaskFactory {

    public static EvaluationTask forMode(ImplementationModeType role) {
        switch (Config.getInstance().getEvaluator()) {
            case TESTSUITE:
                switch (role) {
                    case SERVER:
                        return new TestsuiteServerEvaluationTask();
                    case CLIENT:
                        return new TestsuiteClientEvaluationTask();
                }
                break;
            case FUNCTIONINGTEST:
                switch (role) {
                    case SERVER:
                        return new FunctioningServerTest();
                    case CLIENT:
                        throw new UnsupportedOperationException("Not available yet");
                }
                break;
        }

        throw new UnsupportedOperationException("EvaluationTaskType or ConnectionRole not known");
    }

}

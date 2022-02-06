/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework;

import anonymous.tlstest.framework.execution.TestRunner;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import anonymous.tlstest.framework.config.TestConfig;
import anonymous.tlstest.framework.execution.AnnotatedStateContainer;
import anonymous.tlstest.framework.reporting.ScoreContainer;
import me.tongfei.progressbar.ProgressBar;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Shared global Singleton object that stores information
 * that are used by the JUnit extensions and the test cases.
 */
public class TestContext {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestConfig config;

    private static TestContext instance = null;
    private TestRunner testRunner = null;
    private ParallelExecutor stateExecutor;

    private final Map<String, AnnotatedStateContainer> testResults = new HashMap<>();
    private final Map<String, Boolean> finishedTests = new HashMap<>();
    private boolean initializationFailed = false;

    private TestSiteReport siteReport = null;
    private ClientHelloMessage receivedClientHelloMessage;

    private long totalTests = 0;
    private long testsDone = 0;
    private long testsDisabled = 0;
    private long testsFailed = 0;
    private long testsSucceeded = 0;
    private long performedHandshakes = 0;

    private ScoreContainer scoreContainer = ScoreContainer.forEveryCategory();

    private ProgressBar proggressBar = null;
    private final Date startTime = new Date();
    
    private int serverHandshakesSinceRestart = 0;

    synchronized public static TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
        }
        return TestContext.instance;
    }

    private TestContext() {
        super();
        this.config = new TestConfig();
        this.testRunner = new TestRunner(this.config, this);
    }

    synchronized public TestConfig getConfig() {
        return config;
    }

    synchronized public void setConfig(TestConfig config) {
        this.config = config;
    }

    synchronized public TestRunner getTestRunner() {
        return testRunner;
    }

    synchronized public void setTestRunner(TestRunner testRunner) {
        this.testRunner = testRunner;
    }

    synchronized public Map<String, AnnotatedStateContainer> getTestResults() {
        return testResults;
    }

    synchronized public AnnotatedStateContainer getTestResult(String uniqueId) {
        return testResults.get(uniqueId);
    }

    synchronized public void addTestResult(AnnotatedStateContainer result) {
        testResults.put(result.getUniqueId(), result);
    }

    public ClientHelloMessage getReceivedClientHelloMessage() {
        return receivedClientHelloMessage;
    }

    public void setReceivedClientHelloMessage(ClientHelloMessage receivedClientHelloMessage) {
        this.receivedClientHelloMessage = receivedClientHelloMessage;
    }

    public long getTotalTests() {
        return totalTests;
    }

    public boolean isDocker() {
        return System.getenv("DOCKER") != null;
    }

    synchronized public void setTotalTests(long totalTests) {
        if (!isDocker()) {
            proggressBar = new ProgressBar("Progress", totalTests);
        }

        this.totalTests = totalTests;
    }

    public long getTestsDone() {
        return testsDone;
    }

    synchronized public void testFinished(String uniqueId) {
        finishedTests.put(uniqueId, true);
        this.scoreContainer.mergeWithContainer(testResults.get(uniqueId).getScoreContainer());

        testResults.remove(uniqueId);

        testsDone += 1;
        if (proggressBar != null && !isDocker()) {
            proggressBar.stepBy(1);
        } else if (isDocker()) {
            long timediff = new Date().getTime() - startTime.getTime();
            long minutes = TimeUnit.MILLISECONDS.toMinutes(timediff);
            long remainingSecondsInMillis = timediff - TimeUnit.MINUTES.toMillis(minutes);
            long seconds = TimeUnit.MILLISECONDS.toSeconds(remainingSecondsInMillis);
            LOGGER.info(String.format("%d/%d Tests finished (in %02d:%02d)", testsDone, totalTests, minutes, seconds));
        }
    }

    synchronized public void testDisabled() {
        testsDisabled++;
    }

    synchronized public void testSucceeded() {
        testsSucceeded++;
    }

    synchronized public void testFailed() {
        testsFailed++;
    }

    public ProgressBar getProggressBar() {
        return proggressBar;
    }

    public long getTestsDisabled() {
        return testsDisabled;
    }

    public long getTestsFailed() {
        return testsFailed;
    }

    public long getTestsSucceeded() {
        return testsSucceeded;
    }

    public Date getStartTime() {
        return startTime;
    }

    public TestSiteReport getSiteReport() {
        return siteReport;
    }

    public void setSiteReport(TestSiteReport siteReport) {
        this.siteReport = siteReport;
    }

    public ParallelExecutor getStateExecutor() {
        return stateExecutor;
    }

    public void setStateExecutor(ParallelExecutor stateExecutor) {
        this.stateExecutor = stateExecutor;
    }

    public synchronized int getServerHandshakesSinceRestart() {
        return serverHandshakesSinceRestart;
    }

    public synchronized void resetServerHandshakesSinceRestart() {
        this.serverHandshakesSinceRestart = 0;
    }
    
    public synchronized void increaseServerHandshakesSinceRestart() {
        this.serverHandshakesSinceRestart += 1;
    }

    public long getPerformedHandshakes() {
        return performedHandshakes;
    }

    public void increasePerformedHandshakes(long performedHandshakes) {
        this.performedHandshakes += performedHandshakes;
    }

    public boolean testIsFinished(String uniqueId) {
        return finishedTests.containsKey(uniqueId);
    }

    public ScoreContainer getScoreContainer() {
        return scoreContainer;
    }
}

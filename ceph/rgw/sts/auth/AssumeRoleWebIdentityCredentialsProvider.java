package ceph.rgw.sts.auth;

import com.amazonaws.AmazonClientException;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.retry.PredefinedBackoffStrategies;
import com.amazonaws.retry.RetryPolicy;
import com.amazonaws.retry.RetryUtils;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.amazonaws.services.securitytoken.model.IDPCommunicationErrorException;
import com.amazonaws.services.securitytoken.model.InvalidIdentityTokenException;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;
import java.util.concurrent.Callable;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class AssumeRoleWebIdentityCredentialsProvider implements AWSSessionCredentialsProvider, Closeable {
	
    static final Logger logger = Logger.getLogger(AssumeRoleWebIdentityCredentialsProvider.class);
    static final String LOG_PROPERTIES_FILE = "log4j.properties";

    /**
     * The client for starting STS sessions.
     */
    private final AWSSecurityTokenService securityTokenService;

    private final RefreshTokenService refreshTokenService;
    /**
     * The arn of the role to be assumed.
     */
    private final String roleArn;

    /**
     * An identifier for the assumed role session.
     */
    private final String roleSessionName;

    /**
     * Absolute path to the JWT file containing the web identity token.
     */
    private String webIdentityTokenFile;
    
    private String webIdentityToken;
    
    private final String policy;
    
    private final Integer durationInSeconds;
    
    private final Callable<SessionCredentialsHolder> refreshCallable = new Callable<SessionCredentialsHolder>() {
        @Override
        public SessionCredentialsHolder call() throws Exception {
            return newSession();
        }
    };
    
    private final Callable<RefreshTokenResult> tokenRefreshCallable = new Callable<RefreshTokenResult>() {
        @Override
        public RefreshTokenResult call() throws Exception {
            return newToken();
        }
    };

    /**
     * Handles the refreshing of sessions. Ideally this should be final but #setSTSClientEndpoint
     * forces us to create a new one.
     */
    private volatile RefreshableTask<SessionCredentialsHolder> refreshableTask;
    
    private volatile RefreshableTask<RefreshTokenResult> tokenRefreshableTask;

    private RefreshableTask<SessionCredentialsHolder> createRefreshableTask() {
        return new RefreshableTask.Builder<SessionCredentialsHolder>()
                .withRefreshCallable(refreshCallable)
                .withBlockingRefreshPredicate(new ShouldDoBlockingSessionRefresh())
                .withAsyncRefreshPredicate(new ShouldDoAsyncSessionRefresh()).build();
    }
    
    /*
     * Handles the refreshing of the webidentity token
     */
    private RefreshableTask<RefreshTokenResult> createTokenRefreshableTask() {
        return new RefreshableTask.Builder<RefreshTokenResult>()
                .withRefreshCallable(tokenRefreshCallable)
                .withBlockingRefreshPredicate(new ShouldDoBlockingTokenRefresh())
                .withAsyncRefreshPredicate(new ShouldDoAsyncTokenRefresh()).build();
    }

    /**
     * The following private constructor reads state from the builder and sets the appropriate
     * parameters accordingly
     * <p>
     * When public constructors are called, this constructors is deferred to with a null value for
     * roleExternalId and endpoint The inner Builder class can be used to construct an object that
     * actually has a value for roleExternalId and endpoint
     *
     * @throws IllegalArgumentException if both an AWSCredentials and AWSCredentialsProvider have
     *                                  been set on the builder
     */
    private AssumeRoleWebIdentityCredentialsProvider(Builder builder) {
    	Properties logProperties = new Properties();
        
        try {
            // load log4j properties configuration file
            logProperties.load(new FileInputStream(LOG_PROPERTIES_FILE));
            PropertyConfigurator.configure(logProperties);
            logger.info("Logging initialized.");
        } catch (IOException e) {
            logger.error("Unable to load logging property :", e);
        }
        this.roleArn = builder.roleArn;
        this.roleSessionName = builder.roleSessionName;
        this.durationInSeconds = builder.durationInSeconds;
        this.policy = builder.policy;
        this.securityTokenService = buildStsClient(builder);
        
        if (builder.refreshToken == null && builder.refreshTokenFile == null &&
        		builder.webIdentityToken == null && builder.webIdentityTokenFile == null) {
            logger.error("You must specify a value either for refreshToken(File) or webIdentityToken(File).");
            throw new NullPointerException(
                    "You must specify a value either for refreshToken(File) or webIdentityToken(File)");
        }
       
        if ((builder.refreshToken != null && !builder.refreshToken.isEmpty()) || 
        		(builder.refreshTokenFile != null && !builder.refreshTokenFile.isEmpty())) {
        	this.refreshTokenService = buildRefreshTokenService(builder);
        	logger.trace("Starting token refresh thread ....");
        	this.refreshTokenService.startRefreshThread();
        	this.tokenRefreshableTask = createTokenRefreshableTask();
    	} else {
    		this.refreshTokenService = null;
    		this.tokenRefreshableTask = null;
		this.webIdentityTokenFile = builder.webIdentityTokenFile;
	        this.webIdentityToken = builder.webIdentityToken;
    	}
    	
        this.refreshableTask = createRefreshableTask();
    }

    /**
     * Construct a new STS client from the settings in the builder.
     *
     * @param builder Configured builder
     * @return New instance of AWSSecurityTokenService
     * @throws IllegalArgumentException if builder configuration is inconsistent
     */
    private static AWSSecurityTokenService buildStsClient(Builder builder) throws IllegalArgumentException {
        if (builder.sts != null) {
            return builder.sts;
        }

        RetryPolicy retryPolicy = new RetryPolicy(
                new StsRetryCondition(),
                new PredefinedBackoffStrategies.SDKDefaultBackoffStrategy(),
                3,
                true);

        ClientConfiguration clientConfiguration = new ClientConfiguration();
        clientConfiguration.setRetryPolicy(retryPolicy);
        
        return AWSSecurityTokenServiceClientBuilder.standard()
                                                   .withClientConfiguration(clientConfiguration)
                                                   .withCredentials(new AWSStaticCredentialsProvider(new AnonymousAWSCredentials()))
                                                   .build();
    }
    
    private static RefreshTokenService buildRefreshTokenService(Builder builder) throws IllegalArgumentException {
        
        return new RefreshTokenService(builder.clientId, builder.clientSecret, builder.idpUrl, builder.refreshToken, builder.refreshTokenFile, builder.isAccessToken);
    }

    @Override
    public AWSSessionCredentials getCredentials() {
        return refreshableTask.getValue().getSessionCredentials();
    }

    @Override
    public void refresh() {
        refreshableTask.forceGetValue();
    }

    public void refreshTokens() {
    	tokenRefreshableTask.forceGetValue();
    }
    /**
     * Starts a new session by sending a request to the AWS Security Token Service (STS) to assume a
     * Role using the long lived AWS credentials. This class then vends the short lived session
     * credentials for the assumed Role sent back from STS.
     */
    private SessionCredentialsHolder newSession() {
    	logger.trace("Refreshing Session ...");
    	if (tokenRefreshableTask != null) {
    		logger.trace("Checking whether to refresh access token...");
		this.webIdentityToken = tokenRefreshableTask.getValue().getToken();
    	}
        AssumeRoleWithWebIdentityRequest assumeRoleRequest = new AssumeRoleWithWebIdentityRequest()
                .withRoleArn(this.roleArn)
                .withWebIdentityToken(getWebIdentityToken())
                .withRoleSessionName(this.roleSessionName)
                .withDurationSeconds(this.durationInSeconds)
                .withPolicy(this.policy);

        AssumeRoleWithWebIdentityResult assumeRoleResult = securityTokenService.assumeRoleWithWebIdentity(assumeRoleRequest);
        return new SessionCredentialsHolder(assumeRoleResult.getCredentials());
    }
    
    private RefreshTokenResult newToken() {
		logger.trace("Refreshing token ...");
		RefreshTokenResult r = refreshTokenService.getRefreshedToken();
		return r;
    }

    private String getWebIdentityToken() {
    	if (this.webIdentityToken != null && !this.webIdentityToken.isEmpty()) {
    		return webIdentityToken;
    	}
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(new FileInputStream(webIdentityTokenFile), "UTF-8"));
            return br.readLine();
        } catch (FileNotFoundException e) {
            throw new SdkClientException("Unable to locate specified web identity token file: " + webIdentityTokenFile);
        } catch (IOException e) {
            throw new SdkClientException("Unable to read web identity token from file: " + webIdentityTokenFile);
        } finally {
            try {
                br.close();
            } catch (Exception ignored) {

            }
        }
    }

    /**
     * Shut down this credentials provider, shutting down the thread that performs asynchronous credential refreshing. This
     * should not be invoked if the credentials provider is still in use by an AWS client.
     */
    @Override
    public void close() {
        refreshableTask.close();
        if (tokenRefreshableTask != null) {
		tokenRefreshableTask.close();
        }
        if (refreshTokenService != null) {
		refreshTokenService.stopThread();
        }
    }

    /**
     * Provides a builder pattern to avoid combinatorial explosion of the number of parameters that
     * are passed to constructors. The builder introspects which parameters have been set and calls
     * the appropriate constructor.
     */
    public static final class Builder {

        private final String roleArn;
        private final String roleSessionName;
        private String webIdentityTokenFile;
        private String webIdentityToken;
        private String policy;
        private Integer durationInSeconds = 0;
        private String clientId;
        private String clientSecret;
        private String idpUrl;
        private String refreshToken;
        private String refreshTokenFile;
        private AWSSecurityTokenService sts;
        private boolean isAccessToken = true;

        public Builder(String roleArn, String roleSessionName) {
            if (roleArn == null || roleSessionName == null) {
                throw new NullPointerException(
                        "You must specify a value for roleArn and roleSessionName");
            }
            this.roleArn = roleArn;
            this.roleSessionName = roleSessionName;
        }

        /**
         * Sets a preconfigured STS client to use for the credentials provider. See {@link
         * com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder} for an easy
         * way to configure and create an STS client.
         *
         * @param sts Custom STS client to use.
         * @return This object for chained calls.
         */
        public Builder withStsClient(AWSSecurityTokenService sts) {
            this.sts = sts;
            return this;
        }

        public Builder withDurationSeconds(Integer durationInSeconds) {
            this.durationInSeconds = durationInSeconds;
            return this;
        }
        
        public Builder withPolicy(String policy) {
            this.policy = policy;
            return this;
        }
        
        public Builder withWebIdentityToken(String webIdentityToken) {
            this.webIdentityToken = webIdentityToken;
            return this;
        }
        
        public Builder withWebIdentityTokenFile(String webIdentityTokenFile) {
            this.webIdentityTokenFile = webIdentityTokenFile;
            return this;
        }
        
        public Builder withRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }
        
        public Builder withRefreshTokenFile(String refreshTokenFile) {
            this.refreshTokenFile = refreshTokenFile;
            return this;
        }
        
        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }
        
        public Builder withClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }
        
        public Builder withIdpUrl(String idpUrl) {
            this.idpUrl = idpUrl;
            return this;
        }
        
        public Builder withIsAccessToken(boolean isAccessToken) {
            this.isAccessToken = isAccessToken;
            return this;
        }

        /**
         * Build the configured provider
         *
         * @return the configured STSAssumeRoleSessionCredentialsProvider
         */
        public AssumeRoleWebIdentityCredentialsProvider build() {
        	return new AssumeRoleWebIdentityCredentialsProvider(this);
        }
    }

    static class StsRetryCondition implements com.amazonaws.retry.RetryPolicy.RetryCondition {

        @Override
        public boolean shouldRetry(AmazonWebServiceRequest originalRequest,
                                   AmazonClientException exception,
                                   int retriesAttempted) {
            // Always retry on client exceptions caused by IOException
            if (exception.getCause() instanceof IOException) return true;

            if (exception instanceof InvalidIdentityTokenException || 
                    exception.getCause() instanceof InvalidIdentityTokenException) return true;

            if (exception instanceof IDPCommunicationErrorException || 
                    exception.getCause() instanceof IDPCommunicationErrorException) return true;

            // Only retry on a subset of service exceptions
            if (exception instanceof AmazonServiceException) {
                AmazonServiceException ase = (AmazonServiceException)exception;

                /*
                 * For 500 internal server errors and 503 service
                 * unavailable errors, we want to retry, but we need to use
                 * an exponential back-off strategy so that we don't overload
                 * a server with a flood of retries.
                 */
                if (RetryUtils.isRetryableServiceException(ase)) return true;

                /*
                 * Throttling is reported as a 400 error from newer services. To try
                 * and smooth out an occasional throttling error, we'll pause and
                 * retry, hoping that the pause is long enough for the request to
                 * get through the next time.
                 */
                if (RetryUtils.isThrottlingException(ase)) return true;

                /*
                 * Clock skew exception. If it is then we will get the time offset
                 * between the device time and the server time to set the clock skew
                 * and then retry the request.
                 */
                if (RetryUtils.isClockSkewError(ase)) return true;
            }

            return false;
        }

    }
}


package ceph.rgw.sts.auth;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;

import com.amazonaws.annotation.ThreadSafe;
import com.amazonaws.internal.SdkPredicate;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

@ThreadSafe
class ShouldDoBlockingTokenRefresh extends SdkPredicate<RefreshTokenResult> {
	
	static final Logger logger = Logger.getLogger(ShouldDoAsyncTokenRefresh.class);
    static final String LOG_PROPERTIES_FILE = "log4j.properties";

    /**
     * Time before expiry within which token will be renewed synchronously.
     */
    private static final int EXPIRY_TIME_MILLIS = 10 * 1000;
    
    public ShouldDoBlockingTokenRefresh() {
    	Properties logProperties = new Properties();
		
		try {
            // load log4j properties configuration file
            logProperties.load(new FileInputStream(LOG_PROPERTIES_FILE));
            PropertyConfigurator.configure(logProperties);
            logger.info("Logging initialized.");
        } catch (IOException e) {
            logger.error("Unable to load logging property :", e);
        }
    }

    @Override
    public boolean test(RefreshTokenResult token) {
    	logger.info("Testing if token should be refreshed ...");
        return token == null ||
               expiring(token.getAccessTokenExpiration());
    }

    /**
     * Tokens that expire in less than 10 seconds are considered expiring.
     *
     * @param expiry expiration time of an access token
     */
    private static boolean expiring(Date expiry) {
        long timeRemaining = expiry.getTime() - System.currentTimeMillis();
        logger.info("Time remaining to refresh a token in blocking mode is: "+ timeRemaining);
        return timeRemaining <= EXPIRY_TIME_MILLIS;
    }
}

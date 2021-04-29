package ceph.rgw.sts.auth;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import com.amazonaws.annotation.ThreadSafe;
import com.amazonaws.internal.SdkPredicate;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;


@ThreadSafe
class ShouldDoAsyncTokenRefresh extends SdkPredicate<RefreshTokenResult> {
	
	static final Logger logger = Logger.getLogger(ShouldDoAsyncTokenRefresh.class);
    static final String LOG_PROPERTIES_FILE = "log4j.properties";
    /**
     * Time before expiry within which session credentials will be asynchronously refreshed.
     */
    private static final long ASYNC_REFRESH_EXPIRATION_IN_MILLIS = TimeUnit.SECONDS.toMillis(5);
    
    public ShouldDoAsyncTokenRefresh() {
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
        Date expiryTime = token.getAccessTokenExpiration();
        if (expiryTime != null) {
            long timeRemaining = expiryTime.getTime() - System.currentTimeMillis();
            logger.info("Time remaining to refresh a token in asynchronous mode is: "+ timeRemaining);
            return timeRemaining < ASYNC_REFRESH_EXPIRATION_IN_MILLIS;
        }
        return false;
    }
}
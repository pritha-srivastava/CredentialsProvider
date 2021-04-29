package ceph.rgw.sts.auth;

import com.amazonaws.annotation.ThreadSafe;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.model.Credentials;

import java.util.Date;

/**
 * Holder class used to atomically store a session with its expiration time.
 */
@ThreadSafe
final class SessionCredentialsHolder {

    private final AWSSessionCredentials sessionCredentials;
    private final Date sessionCredentialsExpiration;

    SessionCredentialsHolder(Credentials credentials) {
        this.sessionCredentials = new BasicSessionCredentials(credentials.getAccessKeyId(),
                                                              credentials.getSecretAccessKey(),
                                                              credentials.getSessionToken());
        this.sessionCredentialsExpiration = credentials.getExpiration();
    }

    public AWSSessionCredentials getSessionCredentials() {
        return sessionCredentials;
    }

    public Date getSessionCredentialsExpiration() {
        return sessionCredentialsExpiration;
    }
}

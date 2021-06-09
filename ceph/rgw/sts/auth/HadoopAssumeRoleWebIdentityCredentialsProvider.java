package ceph.rgw.sts.auth;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.hadoop.conf.Configuration;

import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class HadoopAssumeRoleWebIdentityCredentialsProvider implements AWSSessionCredentialsProvider {
	static final Logger logger = Logger.getLogger(HadoopAssumeRoleWebIdentityCredentialsProvider.class);
    static final String LOG_PROPERTIES_FILE = "log4j.properties";

	public static final String NAME
    = "ceph.rgw.sts.auth.HadoopAssumeRoleWebIdentityCredentialsProvider";
	private AssumeRoleWebIdentityCredentialsProvider credsProvider;
	public HadoopAssumeRoleWebIdentityCredentialsProvider(Configuration conf) {
		Properties logProperties = new Properties();
		
		try {
            // load log4j properties configuration file
            logProperties.load(new FileInputStream(LOG_PROPERTIES_FILE));
            PropertyConfigurator.configure(logProperties);
            logger.info("Logging initialized.");
        } catch (IOException e) {
            logger.error("Unable to load logging property :", e);
        }

		String roleArn = conf.get(org.apache.hadoop.fs.s3a.Constants.ASSUMED_ROLE_ARN);
		String roleSessionName = conf.get(org.apache.hadoop.fs.s3a.Constants.ASSUMED_ROLE_SESSION_NAME);
		String duration = org.apache.hadoop.fs.s3a.Constants.ASSUMED_ROLE_SESSION_DURATION;
		char lastChar = duration.charAt(duration.length() - 1);
		Integer durationInSeconds = 15 * 60;
		if (lastChar == 'm') {
			durationInSeconds = (Integer.parseInt(duration.substring(duration.length() - 2))) * 60;
		} else if (lastChar == 'h') {
			durationInSeconds = (Integer.parseInt(duration.substring(duration.length() - 2))) * 3600;
		}
		String policy = conf.get(org.apache.hadoop.fs.s3a.Constants.ASSUMED_ROLE_POLICY);
		String webIdentityTokenFile = conf.get("fs.s3a.webidentitytokenfile");
		String webIdentityToken = conf.get("fs.s3a.webidentitytoken");
		String stsEndpoint = conf.get(org.apache.hadoop.fs.s3a.Constants.ASSUMED_ROLE_STS_ENDPOINT);
		
		String clientId = conf.get("fs.s3a.clientId");
		String clientSecret = conf.get("fs.s3a.clientSecret");
		String idpUrl = conf.get("fs.s3a.idpUrl");
		String refreshToken = conf.get("fs.s3a.refreshToken");
		String refreshTokenFile = conf.get("fs.s3a.refreshTokenFile");
		String isAccessTokenStr = conf.get("fs.s3a.isAccessToken");
		boolean isAccessToken = true;
		if (isAccessTokenStr != null && !isAccessTokenStr.isEmpty()) {
			isAccessToken = Boolean.parseBoolean(isAccessTokenStr);
		}
		
		logger.trace("roleArn:" + roleArn);
		logger.trace("roleSessionName: " + roleSessionName);
		logger.trace("durationInSeconds: " + durationInSeconds);
		logger.trace("policy: " + policy);
		logger.trace("webIdentityTokenFile: " + webIdentityTokenFile);
		logger.trace("webIdentityToken: " + webIdentityToken);
		logger.trace("stsEndpoint: " + stsEndpoint);
		logger.trace("clientId: " + clientId);
		logger.trace("clientSecret: " + clientSecret);
		logger.trace("idpUrl: " + idpUrl);
		logger.trace("refreshToken: " + refreshToken);
		logger.trace("refreshTokenFile: " + refreshTokenFile);
		logger.trace("isAccessToken: " + isAccessToken);

		EndpointConfiguration endpoint = new EndpointConfiguration(stsEndpoint, "");
        
        AWSSecurityTokenService sts = AWSSecurityTokenServiceClientBuilder.standard()
        								.withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("", "")))
        								.withEndpointConfiguration(endpoint)
        								.build();
		credsProvider = new AssumeRoleWebIdentityCredentialsProvider.Builder(roleArn, roleSessionName)
							.withStsClient(sts)
							.withPolicy(policy)
							.withDurationSeconds(durationInSeconds)
							.withWebIdentityTokenFile(webIdentityTokenFile)
							.withWebIdentityToken(webIdentityToken)
							.withClientId(clientId)
							.withClientSecret(clientSecret)
							.withIdpUrl(idpUrl)
							.withRefreshToken(refreshToken)
							.withRefreshTokenFile(refreshTokenFile)
							.withIsAccessToken(isAccessToken)
							.build();
    }
	
	@Override
	public AWSSessionCredentials getCredentials() {
		return credsProvider.getCredentials();
	}
	
	@Override
	public void refresh() {
		credsProvider.refresh();
	}

	@Override
	public String toString() {
	    return getClass().getSimpleName();
	}

	public void close() {
		credsProvider.close();
	}
}

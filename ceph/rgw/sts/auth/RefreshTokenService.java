package ceph.rgw.sts.auth;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.json.JSONException;
import org.json.JSONObject;

import com.amazonaws.SdkClientException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class RefreshTokenService extends Thread implements Closeable {
	static final Logger logger = Logger.getLogger(RefreshTokenService.class);
    static final String LOG_PROPERTIES_FILE = "log4j.properties";

	private String clientId;
	private String clientSecret;
	private String idpUrl;
	private RefreshTokenResult result = null;
	private String refreshToken;
	private String refreshTokenFile;
	private final AtomicBoolean refreshInProgress = new AtomicBoolean(false);
	private final Lock lock = new ReentrantLock();
	private volatile boolean threadExit = false;
	private boolean isAccessToken;
	private long refreshExpirationInMins;

	public void setClientId(String clientId) {
        this.clientId = clientId;
    }
	
	public String getClientId() {
        return this.clientId;
    }

	public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
	
	public String getClientSecret() {
        return this.clientSecret;
    }
	
	public void setIDPUrl(String idpUrl) {
        this.idpUrl = idpUrl;
    }
	
	public String getIDPUrl() {
        return this.idpUrl;
    }

	public RefreshTokenService (String clientId, String clientSecret, String idpUrl, String refreshToken, String refreshTokenFile, long refreshExpirationInMins, boolean isAccessToken) {
		Properties logProperties = new Properties();
		
		try {
            // load log4j properties configuration file
            logProperties.load(new FileInputStream(LOG_PROPERTIES_FILE));
            PropertyConfigurator.configure(logProperties);
            logger.info("Logging initialized.");
        } catch (IOException e) {
            logger.error("Unable to load logging property :", e);
        }
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.idpUrl = idpUrl;
        this.refreshToken = refreshToken;
        this.refreshTokenFile = refreshTokenFile;
        this.isAccessToken = isAccessToken;
	this.refreshExpirationInMins = refreshExpirationInMins;
    }
	
	private String getRefreshToken() {
		if (this.refreshToken != null && !this.refreshToken.isEmpty()) {
    		return refreshToken;
    	}
		
		BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(new FileInputStream(this.refreshTokenFile), "UTF-8"));
            return br.readLine();
        } catch (FileNotFoundException e) {
            throw new SdkClientException("Unable to locate specified refresh token file: " + this.refreshTokenFile);
        } catch (IOException e) {
            throw new SdkClientException("Unable to read refresh token from file: " + this.refreshTokenFile);
        } finally {
            try {
                br.close();
            } catch (Exception ignored) {

            }
        }
	}

	public void close() {
		stopThread();
		stop();
	}

	public void stopThread() {
    	threadExit = true;
     }
	
	//Thread to refresh the 'refresh tokens'
	public void run() {
		while(!threadExit) {
			if (refreshInProgress.get() == false) {
				refreshToken();
			} else {
				do {
					if (refreshInProgress.get() == false) {
						break;
					}
					logger.debug("Waiting for token to be refreshed...");
				}while(refreshInProgress.get() == true);
			}
			long delay_in_millis = 0;
			lock.lock();
			if (this.result == null) {
				threadExit = true;	
			} else {
				delay_in_millis = this.result.getRefreshExpiration().getTime() - System.currentTimeMillis() - 1*1000;
			}
        	lock.unlock();
        	logger.info("Thread sleeping to refresh token for milliseconds: " + delay_in_millis);
        	try {
				Thread.sleep(delay_in_millis);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
		
	}
	
	public void startRefreshThread() {
		start();
	}
	
	public RefreshTokenResult getRefreshedToken() {
		RefreshTokenResult t;
		if (refreshInProgress.get() == false) {
			refreshToken();
		} else {
			do {
				if (refreshInProgress.get() == false || threadExit == true) {
					break;
				}
				logger.debug("Waiting for token to be refreshed...");
			}while(refreshInProgress.get() == true);
		}
		lock.lock();
		t = this.result;
		lock.unlock();
		return t;
	}

	public void refreshToken() {
		if (refreshInProgress.compareAndSet(false, true)) {
    		logger.debug("Refreshing access and refresh tokens ...");
			String accessToken="", idToken="", newRefreshToken="";
			java.util.Date refreshExpiration = null, tokenExpiration = null;
			String refreshToken = getRefreshToken();
			String error = null;
			
			String access_command = "curl -k -s -S -X POST -H Content-Type:application/x-www-form-urlencoded -d scope=openid -d grant_type=refresh_token -d client_id=" + clientId + " -d client_secret=" + clientSecret + " -d refresh_token=" + refreshToken + " " + idpUrl;
	        logger.debug("Command to refresh access token is: " + access_command);
	    	ProcessBuilder new_pb = new ProcessBuilder(access_command.split(" "));
	    	// errorstream of the process will be redirected to standard output
	    	new_pb.redirectErrorStream(true);
	    	// start the process
	    	Process new_proc = null;
			try {
				new_proc = new_pb.start();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	    	/* get the inputstream from the process which would get printed on  
	    	 * the console / terminal
	    	 */
	    	InputStream new_ins = new_proc.getInputStream();
	    	// creating a buffered reader
	    	BufferedReader new_read = new BufferedReader(new InputStreamReader(new_ins));
	    	StringBuilder new_sb = new StringBuilder();
	    	String line = null;
			try {
				line = new_read.readLine();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	    	while(line != null) {
	    		logger.trace("Output line is: " + line);
	    		new_sb.append(line).append("\n");
	            try {
					JSONObject obj = new JSONObject(line);
					if (obj.has("access_token")) {
						accessToken = obj.getString("access_token");
						logger.debug("Access Token is: "+ accessToken);
					}
					if (obj.has("id_token")) {
						idToken = obj.getString("id_token");
						logger.debug("ID Token is: "+ idToken);
					}
					if (obj.has("expires_in")) {
						String expiration = obj.getString("expires_in");
						Integer expiration_seconds = Integer.parseInt(expiration);
						long access_millis = System.currentTimeMillis() + (expiration_seconds * 1000);  
						tokenExpiration = new Date(access_millis);
						logger.debug("Access Expiration Time is: "+ tokenExpiration);
					}
					if (obj.has("refresh_token")) {
						newRefreshToken = obj.getString("refresh_token");
						logger.debug("New refresh Token is: "+ newRefreshToken);
					}
					if (obj.has("refresh_expires_in")) {
						String expiration = obj.getString("refresh_expires_in");
						Integer expiration_seconds = Integer.parseInt(expiration);
						long refresh_millis = System.currentTimeMillis() + (expiration_seconds * 1000);  
						refreshExpiration = new Date(refresh_millis);
						logger.debug("Refresh Expiration Time in token is: "+ refreshExpiration);
					}
					if (obj.has("error")) {
						error = obj.getString("error");
						if (error != null && !error.isEmpty()) {
							String errorMsg = "";
							if (obj.has("error_description")) {
								errorMsg = obj.getString("error_description");
							}
							logger.error("Error returned while refreshing token: "+ error + ": " + errorMsg);
							refreshInProgress.set(false);
							throw new SdkClientException("Error returned while refreshing token: " + error + ": " + errorMsg);
						}
					}
				} catch (JSONException e) {
					logger.trace("Not valid JSON, continuing ...");
				}
	            try {
					line = new_read.readLine();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	        }
	    	logger.trace("Curl response for getting access token is: "+ new_sb.toString());
	    	try {
				new_proc.waitFor();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	int exitCode = new_proc.exitValue();
	    	logger.trace("Exitcode of new process is: "+ exitCode);
	    	new_proc.destroy();
	    	
	    	lock.lock();
	    	if (error != null && !error.isEmpty()) {
	    		this.result = null;
	    	} else {
	    		if (refreshExpiration == null) {
	    			if (this.refreshExpirationInMins != 0) {
		    			long refresh_millis = System.currentTimeMillis() + (this.refreshExpirationInMins * 60 * 1000);  
						refreshExpiration = new Date(refresh_millis);
						logger.debug("Refresh Expiration Time from config option is: "+ refreshExpiration);
	    			} else {
	    				logger.debug("No refresh Expiration Time found");
	    				throw new SdkClientException("No refreshExpirationTime found");
	    			}
	    		}
		    	if (this.result == null) {
		    		if (this.isAccessToken) {
		    			this.result = new RefreshTokenResult(accessToken, newRefreshToken, refreshExpiration, tokenExpiration);
		    		} else
		    		{
		    			this.result = new RefreshTokenResult(idToken, newRefreshToken, refreshExpiration, tokenExpiration);
		    		}
		    	} else {
		    		if (this.isAccessToken) {
		    			this.result.setToken(accessToken);
		    		} else {
		    			this.result.setToken(idToken);
		    		}
			    	this.result.setRefreshToken(newRefreshToken);
			    	this.result.setTokenExpiration(tokenExpiration);
			    	this.result.setRefreshExpiration(refreshExpiration);
		    	}
		    	this.refreshToken = newRefreshToken;
		    	
	    	}
	    	lock.unlock();
	    	refreshInProgress.set(false);
	    	logger.trace("refreshToken Exiting ... ");
		}
	}
	
}

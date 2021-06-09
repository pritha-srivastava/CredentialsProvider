package ceph.rgw.sts.auth;

public class RefreshTokenResult {
	private String token; //Access Token or ID Token based on flag
	private String refreshToken;
	private java.util.Date refreshExpiration;
	private java.util.Date tokenExpiration;
	
	public RefreshTokenResult(String token, String refreshToken, java.util.Date refreshExpiration, java.util.Date tokenExpiration) {
		this.token = token;
		this.refreshToken = refreshToken;
		this.refreshExpiration = refreshExpiration;
		this.tokenExpiration = tokenExpiration;
	}

	public void setToken(String token) {
		this.token = token;
	}
	
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	public String getToken() {
		return this.token;
	}
	
	public String getRefreshToken() {
		return this.refreshToken;
	}
	
	public java.util.Date getRefreshExpiration() {
		return this.refreshExpiration;
	}
	
	public void setRefreshExpiration(java.util.Date refreshExpiration) {
		this.refreshExpiration = refreshExpiration;
	}
	
	public java.util.Date getTokenExpiration() {
		return this.tokenExpiration;
	}
	
	public void setTokenExpiration(java.util.Date tokenExpiration) {
		this.tokenExpiration = tokenExpiration;
	}
}

package ceph.rgw.sts.auth;

public class RefreshTokenResult {
	private String accessToken;
	private String refreshToken;
	private String idToken;
	private java.util.Date refreshExpiration;
	private java.util.Date accessTokenExpiration;
	
	public RefreshTokenResult(String accessToken, String idToken, String refreshToken, java.util.Date refreshExpiration, java.util.Date accessTokenExpiration) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.idToken = idToken;
		this.refreshExpiration = refreshExpiration;
		this.accessTokenExpiration = accessTokenExpiration;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
	public void setIdToken(String idToken) {
		this.idToken = idToken;	
	}
	
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	public String getAccessToken() {
		return this.accessToken;
	}
	
	public String getIdToken() {
		return this.idToken;
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
	
	public java.util.Date getAccessTokenExpiration() {
		return this.accessTokenExpiration;
	}
	
	public void setAccessTokenExpiration(java.util.Date accessTokenExpiration) {
		this.accessTokenExpiration = accessTokenExpiration;
	}
}

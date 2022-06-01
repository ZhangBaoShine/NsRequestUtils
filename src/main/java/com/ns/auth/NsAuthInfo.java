package com.ns.auth;

/**
 * NS认证信息Vo
 *
 * @author zhangbs
 * @version 2021-05-28
 */
public class NsAuthInfo {

    public NsAuthInfo(String realm, String url, String accessToken, String tokenSecret, String consumerKey, String consumerSecret) {
        setRealm(realm);
        setUrl(url);
        setAccessToken(accessToken);
        setTokenSecret(tokenSecret);
        setConsumerKey(consumerKey);
        setConsumerSecret(consumerSecret);
    }

    private String url;
    private String accessToken;
    private String tokenSecret;
    private String consumerKey;
    private String consumerSecret;
    private String realm;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public String getConsumerSecret() {
        return consumerSecret;
    }

    public void setConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }
}

package org.scribe.oauth;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;

public class OAuth20ServiceImpl implements OAuthService
{
  private static final String VERSION = "2.0";
  
  private final DefaultApi20 api;
  private final OAuthConfig config;

private boolean trustAllCerts;
  
  /**
   * Default constructor
   * 
   * @param api OAuth2.0 api information
   * @param config OAuth 2.0 configuration param object
   */
  public OAuth20ServiceImpl(DefaultApi20 api, OAuthConfig config)
  {
    this.api = api;
    this.config = config;
  }

  /**
   * {@inheritDoc}
   */
  public Token getAccessToken(Token requestToken, Verifier verifier)
  {
    Verb verb = api.getAccessTokenVerb();
    OAuthRequest request = new OAuthRequest(verb, api.getAccessTokenEndpoint());
    request.setTrustAllCerts(trustAllCerts);
    if (verb == Verb.GET) {
        request.addQuerystringParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
        request.addQuerystringParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
        // In case of Client Credentials, verfier is not required
        if(verifier != null) request.addQuerystringParameter(OAuthConstants.CODE, verifier.getValue());
        request.addQuerystringParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
        if(config.hasScope()) request.addQuerystringParameter(OAuthConstants.SCOPE, config.getScope());
        if(config.hasGrantType()) request.addQuerystringParameter(OAuthConstants.GRANT_TYPE, config.getGrantType());
    } else if (verb == Verb.POST) {
        request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
        request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
        // In case of Client Credentials, verfier is not required
        if(verifier != null) request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
        request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
        if(config.hasScope()) request.addBodyParameter(OAuthConstants.SCOPE, config.getScope());
        if(config.hasGrantType()) request.addBodyParameter(OAuthConstants.GRANT_TYPE, config.getGrantType());
    }
    Response response = request.send();
    return api.getAccessTokenExtractor().extract(response.getBody());
  }

  /**
   * {@inheritDoc}
   */
  public Token getRequestToken()
  {
    throw new UnsupportedOperationException("Unsupported operation, please use 'getAuthorizationUrl' and redirect your users there");
  }

  /**
   * {@inheritDoc}
   */
  public String getVersion()
  {
    return VERSION;
  }

  /**
   * {@inheritDoc}
   */
  public void signRequest(Token accessToken, OAuthRequest request)
  {
    if (api.getAccessTokenVerb() == Verb.GET)
        request.addQuerystringParameter(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
    else if (api.getAccessTokenVerb() == Verb.POST)
        request.addBodyParameter(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
  }

  /**
   * {@inheritDoc}
   */
  public String getAuthorizationUrl(Token requestToken)
  {
    return api.getAuthorizationUrl(config);
  }

  @Override
  public void setTrustAllCerts(boolean trustAllCerts) {
    this.trustAllCerts = trustAllCerts;
  }
}

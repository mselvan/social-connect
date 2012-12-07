/*
 ===========================================================================
 Copyright (c) 2010 BrickRed Technologies Limited

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sub-license, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 ===========================================================================

 */

package com.nallan.social.provider;

import java.io.InputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import com.nallan.social.AbstractProvider;
import com.nallan.social.AuthProvider;
import com.nallan.social.Contact;
import com.nallan.social.Permission;
import com.nallan.social.Profile;
import com.nallan.social.exception.ServerDataException;
import com.nallan.social.exception.SocialAuthException;
import com.nallan.social.exception.UserDeniedPermissionException;
import com.nallan.social.oauthstrategy.OAuth2;
import com.nallan.social.oauthstrategy.OAuthStrategyBase;
import com.nallan.social.util.AccessGrant;
import com.nallan.social.util.BirthDate;
import com.nallan.social.util.Constants;
import com.nallan.social.util.MethodType;
import com.nallan.social.util.OAuthConfig;
import com.nallan.social.util.Response;

/**
 * OAuth2 Impl for google
 * 
 * @author Manimaran Selvan
 * 
 */
public class GoogleOAuth2Impl extends AbstractProvider implements AuthProvider, Serializable
{

	private static final long serialVersionUID = 8644510564735754296L;
	private static final String PROFILE_URL = "https://www.googleapis.com/oauth2/v1/userinfo";
	private static final Map<String, String> ENDPOINTS;
	private static final Log LOG = LogFactory.getLog(GoogleOAuth2Impl.class);

	private Permission scope;
	private OAuthConfig config;
	private Profile userProfile;
	private AccessGrant accessGrant;
	private OAuthStrategyBase authenticationStrategy;

	// set this to the list of extended permissions you want
	// scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&
	// private static final String[] AllPerms = new String[] { "publish_stream", "email", "user_birthday", "user_location" };
	private static final String[] AllPerms = new String[] { "https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile" };
	private static final String[] AuthPerms = new String[] { "email", "user_birthday", "user_location" };

	static {
		ENDPOINTS = new HashMap<String, String>();
		ENDPOINTS.put(Constants.OAUTH_AUTHORIZATION_URL, "https://accounts.google.com/o/oauth2/auth");
		ENDPOINTS.put(Constants.OAUTH_ACCESS_TOKEN_URL, "https://accounts.google.com/o/oauth2/token");
	}

	/**
	 * Stores configuration for the provider
	 * 
	 * @param providerConfig
	 *            It contains the configuration of application like consumer key and consumer secret
	 * @throws Exception
	 */
	public GoogleOAuth2Impl(final OAuthConfig providerConfig) throws Exception
	{
		config = providerConfig;
		if (config.getCustomPermissions() != null) {
			scope = Permission.CUSTOM;
		}
		authenticationStrategy = new OAuth2(config, ENDPOINTS);
		authenticationStrategy.setPermission(scope);
		authenticationStrategy.setScope(getScope());
	}

	/**
	 * Stores access grant for the provider
	 * 
	 * @param accessGrant
	 *            It contains the access token and other information
	 * @throws Exception
	 */
	@Override
	public void setAccessGrant(final AccessGrant accessGrant) throws Exception
	{
		this.accessGrant = accessGrant;
		authenticationStrategy.setAccessGrant(accessGrant);
	}

	/**
	 * This is the most important action. It redirects the browser to an appropriate URL which will be used for authentication with the provider that has been set using setId()
	 * 
	 */
	@Override
	public String getLoginRedirectURL(final String successUrl) throws Exception
	{
		return authenticationStrategy.getLoginRedirectURL(successUrl);
	}

	/**
	 * Verifies the user when the external provider redirects back to our application.
	 * 
	 * 
	 * @param requestParams
	 *            request parameters, received from the provider
	 * @return Profile object containing the profile information
	 * @throws Exception
	 */

	@Override
	public Profile verifyResponse(final Map<String, String> requestParams) throws Exception
	{
		return doVerifyResponse(requestParams);
	}

	private Profile doVerifyResponse(final Map<String, String> requestParams) throws Exception
	{
		LOG.info("Retrieving Access Token in verify response function");
		if (requestParams.get("error_reason") != null && "user_denied".equals(requestParams.get("error_reason"))) {
			throw new UserDeniedPermissionException();
		}
		accessGrant = authenticationStrategy.verifyResponse(requestParams, MethodType.POST.toString());

		if (accessGrant != null) {
			LOG.debug("Obtaining user profile");
			return authGoogleLogin();
		} else {
			throw new SocialAuthException("Access token not found");
		}
	}

	private Profile authGoogleLogin() throws Exception
	{
		String presp;

		try {
			Response response = authenticationStrategy.executeFeed(PROFILE_URL);
			presp = response.getResponseBodyAsString(Constants.ENCODING);
		} catch (Exception e) {
			throw new SocialAuthException("Error while getting profile from " + PROFILE_URL, e);
		}
		try {
			LOG.debug("User Profile : " + presp);
			JSONObject resp = new JSONObject(presp);
			Profile p = new Profile();
			p.setValidatedId(resp.getString("id"));
			p.setFirstName(resp.getString("given_name"));
			p.setLastName(resp.getString("family_name"));
			p.setEmail(resp.getString("email"));
			if (resp.has("location")) {
				p.setLocation(resp.getJSONObject("location").getString("name"));
			}
			if (resp.has("birthday")) {
				String bstr = resp.getString("birthday");
				String[] arr = bstr.split("-");
				BirthDate bd = new BirthDate();
				if (arr.length > 0) {
					bd.setYear(Integer.parseInt(arr[2]));
				}
				if (arr.length > 1) {
					bd.setMonth(Integer.parseInt(arr[0]));
				}
				if (arr.length > 2) {
					bd.setDay(Integer.parseInt(arr[1]));
				}
				p.setDob(bd);
			}
			if (resp.has("gender")) {
				p.setGender(resp.getString("gender"));
			}
			if (resp.has("picture")) {
				p.setProfileImageURL(resp.getString("picture"));
			}
			if (resp.has("locale")) {
				String locale = resp.getString("locale");
				if (locale != null) {
					String a[] = locale.split("-");
					p.setLanguage(a[0]);
					p.setCountry(a[1]);
				}
			}
			p.setProviderId(getProviderId());
			userProfile = p;
			return p;

		} catch (Exception ex) {
			throw new ServerDataException("Failed to parse the user profile json : " + presp, ex);
		}
	}

	/**
	 * Updates the status on the chosen provider if available. This may not be implemented for all providers.
	 * 
	 * @param msg
	 *            Message to be shown as user's status
	 * @throws Exception
	 */

	@Override
	public void updateStatus(final String msg) throws Exception
	{
		throw new SocialAuthException("Not supported yet!");
	}

	/**
	 * Gets the list of contacts of the user. this may not be available for all providers.
	 * 
	 * @return List of contact objects representing Contacts. Only name will be available
	 */

	@Override
	public List<Contact> getContactList() throws Exception
	{
		throw new SocialAuthException("Not supported yet!");
	}

	/**
	 * Logout
	 */
	@Override
	public void logout()
	{
		accessGrant = null;
		authenticationStrategy.logout();
	}

	/**
	 * 
	 * @param p
	 *            Permission object which can be Permission.AUHTHENTICATE_ONLY, Permission.ALL, Permission.DEFAULT
	 */
	@Override
	public void setPermission(final Permission p)
	{
		LOG.debug("Permission requested : " + p.toString());
		this.scope = p;
		authenticationStrategy.setPermission(this.scope);
		authenticationStrategy.setScope(getScope());
	}

	/**
	 * Makes HTTP request to a given URL.It attaches access token in URL.
	 * 
	 * @param url
	 *            URL to make HTTP request.
	 * @param methodType
	 *            Method type can be GET, POST or PUT
	 * @param params
	 *            Not using this parameter in Google API function
	 * @param headerParams
	 *            Parameters need to pass as Header Parameters
	 * @param body
	 *            Request Body
	 * @return Response object
	 * @throws Exception
	 */
	@Override
	public Response api(final String url, final String methodType, final Map<String, String> params, final Map<String, String> headerParams, final String body) throws Exception
	{
		LOG.info("Calling api function for url	:	" + url);
		Response response = null;
		try {
			response = authenticationStrategy.executeFeed(url, methodType, params, headerParams, body);
		} catch (Exception e) {
			throw new SocialAuthException("Error while making request to URL : " + url, e);
		}
		return response;
	}

	/**
	 * Retrieves the user profile.
	 * 
	 * @return Profile object containing the profile information.
	 */
	@Override
	public Profile getUserProfile() throws Exception
	{
		if (userProfile == null && accessGrant != null) {
			authGoogleLogin();
		}
		return userProfile;
	}

	@Override
	public AccessGrant getAccessGrant()
	{
		return accessGrant;
	}

	@Override
	public String getProviderId()
	{
		return config.getId();
	}

	@Override
	public Response uploadImage(final String message, final String fileName, final InputStream inputStream) throws Exception
	{
		throw new SocialAuthException("Not supported yet!");
	}

	private String getScope()
	{
		StringBuffer result = new StringBuffer();
		String arr[] = null;
		if (Permission.AUTHENTICATE_ONLY.equals(scope)) {
			arr = AuthPerms;
		} else if (Permission.CUSTOM.equals(scope) && config.getCustomPermissions() != null) {
			arr = config.getCustomPermissions().split(",");
		} else {
			arr = AllPerms;
		}
		result.append(arr[0]);
		for (int i = 1; i < arr.length; i++) {
			result.append(",").append(arr[i]);
		}
		return result.toString();
	}
}
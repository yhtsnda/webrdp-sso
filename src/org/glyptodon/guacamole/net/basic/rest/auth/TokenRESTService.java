package org.glyptodon.guacamole.net.basic.rest.auth;

import com.google.inject.Inject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.DatatypeConverter;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleResourceNotFoundException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.UserContext;
import org.glyptodon.guacamole.net.basic.GuacamoleSession;
import org.glyptodon.guacamole.net.basic.rest.APIRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/tokens")
@Produces({"application/json"})
public class TokenRESTService
{
  private static final Logger logger = LoggerFactory.getLogger(TokenRESTService.class);

  @Inject
  private AuthenticationService authenticationService;

  private Credentials getCredentials(HttpServletRequest request, String username, String password)
  {
    if ((username == null) && (password == null))
    {
      String authorization = request.getHeader("Authorization");
      if ((authorization != null) && (authorization.startsWith("Basic ")))
      {
        try
        {
          String basicBase64 = authorization.substring(6);
          String basicCredentials = new String(DatatypeConverter.parseBase64Binary(basicBase64), "UTF-8");

          int colon = basicCredentials.indexOf(58);
          if (colon != -1) {
            username = basicCredentials.substring(0, colon);
            password = basicCredentials.substring(colon + 1);
          }
          else {
            logger.debug("Invalid HTTP Basic \"Authorization\" header received.");
          }

        }
        catch (UnsupportedEncodingException e)
        {
          throw new UnsupportedOperationException("Unexpected lack of UTF-8 support.", e);
        }

      }

    }

    Credentials credentials = new Credentials();
    credentials.setUsername(username);
    credentials.setPassword(password);
    credentials.setRequest(request);
    credentials.setSession(request.getSession(true));

    return credentials;
  }

  @POST
  public APIAuthenticationResult createToken(@FormParam("username") String username, @FormParam("password") String password, @FormParam("token") String token, @Context HttpServletRequest consumedRequest, MultivaluedMap<String, String> parameters)
    throws GuacamoleException
  {
    HttpServletRequest request = new APIRequest(consumedRequest, parameters);
// 与一级平台sso集成
    logger.info("old username:{}",username);
    username = consumedRequest.getRemoteUser();
    password = "123456";
    logger.info("new username:{}",username);
    
    Credentials credentials = getCredentials(request, username, password);
 

    token = this.authenticationService.authenticate(credentials, token);

    GuacamoleSession session = this.authenticationService.getGuacamoleSession(token);
    if (session == null) {
      throw new GuacamoleResourceNotFoundException("No such token.");
    }

    List<UserContext> userContexts = session.getUserContexts();
    List authProviderIdentifiers = new ArrayList(userContexts.size());
    for (UserContext userContext : userContexts) {
      authProviderIdentifiers.add(userContext.getAuthenticationProvider().getIdentifier());
    }

    AuthenticatedUser authenticatedUser = session.getAuthenticatedUser();

    return new APIAuthenticationResult(token, authenticatedUser
      .getIdentifier(), authenticatedUser
      .getAuthenticationProvider().getIdentifier(), authProviderIdentifiers);
  }

  @DELETE
  @Path("/{token}")
  public void invalidateToken(@PathParam("token") String authToken,@Context HttpServletRequest request,@Context HttpServletResponse response)
    throws GuacamoleException, IOException
  {
    if (!this.authenticationService.destroyGuacamoleSession(authToken))
      throw new GuacamoleResourceNotFoundException("No such token."); 
    logger.info("logout---");
    request.getRequestDispatcher("https://sso.testplatform.com:8443/cas/logout?service=https://sso.testplatform.com:8443/cas/login");
    logger.info("logout++++");
  }
}
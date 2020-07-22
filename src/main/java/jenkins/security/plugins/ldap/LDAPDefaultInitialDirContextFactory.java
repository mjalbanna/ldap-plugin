package jenkins.security.plugins.ldap;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Map;
import java.util.StringTokenizer;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLSession;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.ldap.LdapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;

public class LDAPDefaultInitialDirContextFactory extends DefaultInitialDirContextFactory {

	// ~ Static fields/initializers
	// =====================================================================================

	private static final Log logger = LogFactory.getLog(LDAPDefaultInitialDirContextFactory.class);
	private static final String CONNECTION_POOL_KEY = "com.sun.jndi.ldap.connect.pool";
	private static final String AUTH_TYPE_NONE = "none";

	// ~ Instance fields
	// ================================================================================================

	/** Allows extra environment variables to be added at config time. */
	private Map extraEnvVars = null;
	StartTlsRequest tlsReq = new StartTlsRequest();
	StartTlsResponse tls = null;
	InitialLdapContext ctx = null;
	SSLSession session = null;

	public StartTlsResponse getTls() {
		return tls;
	}

	public void setTls(StartTlsResponse tls) {
		this.tls = tls;
	}

	/** Type of authentication within LDAP; default is simple. */
	private String authenticationType = "simple";

	/**
	 * The INITIAL_CONTEXT_FACTORY used to create the JNDI Factory. Default is
	 * "com.sun.jndi.ldap.LdapCtxFactory"; you <b>should not</b> need to set this
	 * unless you have unusual needs.
	 */
	private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

	/**
	 * If your LDAP server does not allow anonymous searches then you will need to
	 * provide a "manager" user's DN to log in with.
	 */
	private String managerDn = null;

	public String getManagerDn() {
		return managerDn;
	}

	/** The manager user's password. */
	private String managerPassword = "manager_password_not_set";

	public String getManagerPassword() {
		return managerPassword;
	}

	/** The LDAP url of the server (and root context) to connect to. */
	private String providerUrl;

	/**
	 * The root DN. This is worked out from the url. It is used by client classes
	 * when forming a full DN for bind authentication (for example).
	 */
	private String rootDn = null;

	/**
	 * Use the LDAP Connection pool; if true, then the LDAP environment property
	 * "com.sun.jndi.ldap.connect.pool" is added to any other JNDI properties.
	 */
	private boolean useConnectionPool = true;

	/** Set to true for ldap v3 compatible servers */
	private boolean useLdapContext = true;

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Create and initialize an instance to the LDAP url provided
	 *
	 * @param providerUrl a String of the form
	 *                    <code>ldap://localhost:389/base_dn<code>
	 */
	public LDAPDefaultInitialDirContextFactory(String providerUrl) {
		super(providerUrl);
		this.setProviderUrl(providerUrl);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Set the LDAP url
	 *
	 * @param providerUrl a String of the form
	 *                    <code>ldap://localhost:389/base_dn<code>
	 */
	private void setProviderUrl(String providerUrl) {
		Assert.hasLength(providerUrl, "An LDAP connection URL must be supplied.");

		this.providerUrl = providerUrl;

		StringTokenizer st = new StringTokenizer(providerUrl);

		// Work out rootDn from the first URL and check that the other URLs (if any)
		// match
		while (st.hasMoreTokens()) {
			String url = st.nextToken();
			String urlRootDn = LdapUtils.parseRootDnFromUrl(url);

			logger.info(" URL '" + url + "', root DN is '" + urlRootDn + "'");

			if (rootDn == null) {
				rootDn = urlRootDn;
			} else if (!rootDn.equals(urlRootDn)) {
				throw new IllegalArgumentException("Root DNs must be the same when using multiple URLs");
			}
		}

		// This doesn't necessarily hold for embedded servers.
		// Assert.isTrue(uri.getScheme().equals("ldap"), "Ldap URL must start with
		// 'ldap://'");
	}

	/**
	 * Get the LDAP url
	 *
	 * @return the url
	 */
	private String getProviderUrl() {
		return providerUrl;
	}

	private InitialDirContext connect(Hashtable env) {
		if (logger.isDebugEnabled()) {
			Hashtable envClone = (Hashtable) env.clone();

			if (envClone.containsKey(Context.SECURITY_CREDENTIALS)) {
				envClone.put(Context.SECURITY_CREDENTIALS, "******");
			}

			logger.debug("Creating InitialDirContext with environment " + envClone);
		}

		try {
			String username = (String) env.get(Context.SECURITY_PRINCIPAL);
			String password = (String) env.get(Context.SECURITY_CREDENTIALS);
			env.remove(Context.SECURITY_PRINCIPAL);
			env.remove(Context.SECURITY_CREDENTIALS);
			if (session != null && ctx != null && session.isValid() && tls != null) {
				reconnect(env, username, password);
				if (session.isValid()) {
					return ctx;
				}
			}
			reconnect(env, username, password);
			return ctx;
		} catch (NamingException ne) {
			if ((ne instanceof javax.naming.AuthenticationException)
					|| (ne instanceof OperationNotSupportedException)) {
				throw new BadCredentialsException(
						messages.getMessage("DefaultIntitalDirContextFactory.badCredentials", "Bad credentials"), ne);
			}
			if (ne instanceof CommunicationException) {
				throw new LdapDataAccessException(
						messages.getMessage("DefaultIntitalDirContextFactory.communicationFailure",
								"Unable to connect to LDAP server"),
						ne);
			}
			throw new LdapDataAccessException(messages.getMessage("DefaultIntitalDirContextFactory.unexpectedException",
					"Failed to obtain InitialDirContext due to unexpected exception"), ne);
		} catch (Exception exp) {
			throw new LdapDataAccessException(messages.getMessage("unexpectedException",
					"Failed to obtain InitialDirContext due to unexpected exception"), exp);
		}
	}

	private void reconnect(Hashtable env, String username, String password) throws NamingException, IOException {
		closeConnections();
		ctx = new InitialLdapContext(env, null);
		tlsReq = new StartTlsRequest();
		StartTlsResponse tlsTemp = null;
		try {
			tlsTemp = (StartTlsResponse) ctx.extendedOperation(tlsReq);
		} catch (Exception ne) {
			// sallow to reconnect
		}
		tls = (tlsTemp != null) ? tlsTemp : tls;
		reconfigure(username, password);
	}

	private void closeConnections() {
		try {
			if (tls != null) {
				tls.close();
			}
			tls = null;
			if (ctx != null) {
				ctx.close();
			}
		} catch (NamingException nexp) {
			logger.error("Error closing context:" + nexp.getMessage());
		} catch (IOException iexp) {
			logger.error("Error closing tls:" + iexp.getMessage());
		}
	}

	private void reconfigure(String username, String password) throws IOException, NamingException {
		if (tls != null) {
			//tls.setHostnameVerifier(new CertVerifier());
			session = tls.negotiate();
			ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
			ctx.reconnect(ctx.getConnectControls());
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, username);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
		}
	}

	/**
	 * Sets up the environment parameters for creating a new context.
	 *
	 * @return the Hashtable describing the base DirContext that will be created,
	 *         minus the username/password if any.
	 */
	protected Hashtable getEnvironment() {
		Hashtable env = new Hashtable();

		env.put(Context.SECURITY_AUTHENTICATION, authenticationType);
		env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
		env.put(Context.PROVIDER_URL, getProviderUrl());

		if (useConnectionPool) {
			env.put(CONNECTION_POOL_KEY, "true");
		}

		if ((extraEnvVars != null) && (extraEnvVars.size() > 0)) {
			env.putAll(extraEnvVars);
		}

		return env;
	}

	/**
	 * Returns the root DN of the configured provider URL. For example, if the URL
	 * is <tt>ldap://monkeymachine.co.uk:389/dc=acegisecurity,dc=org</tt> the value
	 * will be <tt>dc=acegisecurity,dc=org</tt>.
	 *
	 * @return the root DN calculated from the path of the LDAP url.
	 */
	public String getRootDn() {
		return rootDn;
	}

	/**
	 * Connects anonymously unless a manager user has been specified, in which case
	 * it will bind as the manager.
	 *
	 * @return the resulting context object.
	 */
	public DirContext newInitialDirContext() {
		if (managerDn != null) {
			return newInitialDirContext(managerDn, managerPassword);
		}

		Hashtable env = getEnvironment();
		env.put(Context.SECURITY_AUTHENTICATION, AUTH_TYPE_NONE);

		return connect(env);
	}

	public DirContext newInitialDirContext(String username, String password) {
		Hashtable env = getEnvironment();

		// Don't pool connections for individual users
		if (!username.equals(managerDn)) {
			env.remove(CONNECTION_POOL_KEY);
		}

		env.put(Context.SECURITY_PRINCIPAL, username);
		env.put(Context.SECURITY_CREDENTIALS, password);

		return connect(env);
	}

	public void setAuthenticationType(String authenticationType) {
		Assert.hasLength(authenticationType, "LDAP Authentication type must not be empty or null");
		this.authenticationType = authenticationType;
	}

	/**
	 * Sets any custom environment variables which will be added to the those
	 * returned by the <tt>getEnvironment</tt> method.
	 *
	 * @param extraEnvVars extra environment variables to be added at config time.
	 */
	public void setExtraEnvVars(Map extraEnvVars) {
		Assert.notNull(extraEnvVars, "Extra environment map cannot be null.");
		this.extraEnvVars = extraEnvVars;
	}

	public void setInitialContextFactory(String initialContextFactory) {
		Assert.hasLength(initialContextFactory, "Initial context factory name cannot be empty or null");
		this.initialContextFactory = initialContextFactory;
	}

	/**
	 * Sets the directory user to authenticate as when obtaining a context using the
	 * <tt>newInitialDirContext()</tt> method. If no name is supplied then the
	 * context will be obtained anonymously.
	 *
	 * @param managerDn The name of the "manager" user for default authentication.
	 */
	public void setManagerDn(String managerDn) {
		Assert.hasLength(managerDn, "Manager user name  cannot be empty or null.");
		this.managerDn = managerDn;
	}

	/**
	 * Sets the password which will be used in combination with the manager DN.
	 *
	 * @param managerPassword The "manager" user's password.
	 */
	public void setManagerPassword(String managerPassword) {
		Assert.hasLength(managerPassword, "Manager password must not be empty or null.");
		this.managerPassword = managerPassword;
	}

	/**
	 * Connection pooling is enabled by default for anonymous or "manager"
	 * connections when using the default Sun provider. To disable all connection
	 * pooling, set this property to false.
	 *
	 * @param useConnectionPool whether to pool connections for non-specific users.
	 */
	public void setUseConnectionPool(boolean useConnectionPool) {
		this.useConnectionPool = useConnectionPool;
	}

	public void setUseLdapContext(boolean useLdapContext) {
		this.useLdapContext = useLdapContext;
	}

}

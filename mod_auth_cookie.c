/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * mod_auth_cookie: authentication addon for Apache 2
 *
 * Version 0.2
 * September 2012
 * Enhancements by Greg Anderson (https://github.com/greg-1-anderson)
 *
 * Based on mod_auth_cookie for Apache 2.x by Richard Antony Burton,
 * January 2004 (Version 0.1), which was based on the original
 * concept for Apache 1.3 by Vivek Khera.
 *
 * Allows a cookie to be checked for authentication instead of the Authorization
 * header. This is an addon module to your normal auth module, that will fake
 * normal auth header with data from a cookie. Can be used to allow a form based
 * logon, rather than using the browsers user/password popup dialog. If cookie
 * is not present or contains invalid credentials, normal auth will resume, and
 * normal popup will occur, browser permitting.  If the popup dialog is not
 * desired, a configuration directive may be set to force a redirection to your
 * login page of choice.
 *
 * The configuration directives are compatible with the version for Apache 1.3,
 * although additional options have also been added.
 *
 * Place these directives to your <directory> stanza:
 *   (along with you normal auth config)
 *
 *   AuthCookieName             CookieName
 *   AuthCookieOverride         [ On | Off ] Default = Off
 *   AuthCookieBase64           [ On | Off ] Default = Off
 *   AuthCookieEnv              EnvironmentVariableName
 *   AuthCookieUnauthRedirect   url
 *   AuthCookieEnvRedirect      url
 *   AuthCookieEncrypt          shared_secret
 *
 *   AuthCookieName - the name of the cookie to consult for authorization information
 *
 *   AuthCookieOverride - if request contains both a cookie and an Authorization
 *       header, the cookie will be the one that is used.
 *
 *   AuthCookieBase64 - cookie contains "username:password" already base64 encoded
 *       as would be flowed in the normal Authorization header. This must be enabled
 *       to use the more advanced features such as AuthCookieEnv and AuthCookieEncrypt.
 *
 *   AuthCookieEnv - allows an environment variable to also be set during authenitcation.
 *       The AuthCookieEnv directive specifies the name of the environment variable to
 *       set; the environment variable value is stored after the username and password,
 *       separated by a <tab> character.  Thus, the full contents of the cookie will
 *       be "environment value<tab>username:password".
 *
 *       LIMITATION: AuthCookieEnv is only respected when in AuthCookieBase64 mode.
 *
 *   AuthCookieUnauthRedirect - if the cookie is not set, then redirect to this location.
 *
 *   AuthCookieEnvRedirect - if the cookie does not contain the optional auxiliary
 *       authentication information, then redirect to this location.
 *
 *   AuthCookieEnrypt - cookie is encrypted using the specified encryption key,
 *       which should by very long.  32 characters is good.  The format for the
 *       cookie then becomes "iv-vector mcrypt(data)", where 'data' contains the
 *       full unencrypted cookie value "environment value<tab>username:password".
 *       Sample code to create an encrypted cookie is available in the README
 *       file (php) and in crypt_sample.c.
 *
 *       LIMITATION:  AuthCookieEncrypt is only supported in AuthCookieBase64 mode.
 *       The cookie value should be encrypted and prepended with the IV before being
 *       base-64 encoded.
 *
 * Load using:
 *   LoadModule auth_cookie_module modules/mod_auth_cookie.so
 *
 */

#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#include <mcrypt.h>

typedef struct {
    char *cookie_auth_cookie;
    char *cookie_auth_env;
    char *cookie_auth_env_redirect;
    char *cookie_auth_unauth_redirect;
    char *cookie_auth_encrypt;
    int cookie_auth_base64;
    int cookie_auth_override;
} cookie_auth_config_rec;

static void *create_cookie_auth_dir_config(apr_pool_t *p, char *d)
{
    cookie_auth_config_rec *conf = apr_palloc(p, sizeof(*conf));

	if (conf) {
        /* Set default values. */
        conf->cookie_auth_cookie = NULL;
	conf->cookie_auth_env = NULL;
	conf->cookie_auth_env_redirect = NULL;
	conf->cookie_auth_unauth_redirect = NULL;
	conf->cookie_auth_encrypt = NULL;
        conf->cookie_auth_base64 = 0;
        conf->cookie_auth_override = 0;
	}

    return conf;
}

/*
char* create_des_key(apr_pool_t *pool, char *ascii_key)
{
	char* result = apr_palloc(pool, 8);
	memset(result, '\0', 8);

	int i = 0;
	while(*ascii_key)
	{
		result[i] ^= (*ascii_key++) << 1;
		i = (i + 1) & 7;
	}

	des_setparity(result);

	return result;
}
*/

// If 'redirect' is foo/bar, then redirect to it.  If it is
// foo/bar/%s, then replace the %s with r->uri.
static void compose_and_set_redirect(request_rec *r, const char* redirect) {
	char* composed_redirect = NULL;
	if (ap_strstr_c(redirect, "%s")) {
		composed_redirect = apr_psprintf(r->pool, redirect, r->uri);
 	}
        apr_table_setn(r->headers_out, "Location", composed_redirect ? composed_redirect : redirect);
}

static const command_rec cookie_auth_cmds[] =
{
    AP_INIT_TAKE1("AuthCookieName", ap_set_string_slot,
	 (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_cookie),
	 OR_AUTHCFG, "auth cookie name"),
    AP_INIT_TAKE1("AuthCookieEnv", ap_set_string_slot,
	 (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_env),
	 OR_AUTHCFG, "environment variable name for optional auxiliary auth info"),
     AP_INIT_TAKE1("AuthCookieEnvRedirect", ap_set_string_slot,
	 (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_env_redirect),
	 OR_AUTHCFG, "path to redirect to if optional auxiliary auth info is missing in cookie"),
     AP_INIT_TAKE1("AuthCookieUnauthRedirect", ap_set_string_slot,
	 (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_unauth_redirect),
	 OR_AUTHCFG, "path to redirect to if authentication cookie is not set"),
   AP_INIT_TAKE1("AuthCookieEncrypt", ap_set_string_slot,
	 (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_encrypt),
	 OR_AUTHCFG, "secret key used to DES-encrypt the cookie"),
    AP_INIT_FLAG("AuthCookieOverride", ap_set_flag_slot,
     (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_override),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    AP_INIT_FLAG("AuthCookieBase64", ap_set_flag_slot,
     (void *)APR_OFFSETOF(cookie_auth_config_rec, cookie_auth_base64),
     OR_AUTHCFG, "Limited to 'on' or 'off'"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_cookie_module;

static int check_auth_cookie(request_rec *r)
{

	const char *cookies = NULL, *auth_line = NULL;
	char *cookie = NULL;

    /* Debug. */
	/*ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	    "check_auth_cookie called");*/

	/* Get config for this directory. */
    cookie_auth_config_rec *conf = ap_get_module_config(r->per_dir_config,
		&auth_cookie_module);

    /* Check we have been configured. */
    if (!conf->cookie_auth_cookie) {
        return DECLINED;
    }

	/* Do not override real auth header, unless config instructs us to. */
	if (!conf->cookie_auth_override &&
		apr_table_get(r->headers_in, "Authorization")) {
		if (conf->cookie_auth_env) {
			unsetenv(conf->cookie_auth_env);
		}
		return DECLINED;
	}

	/* todo: protect against xxxCookieNamexxx, regex? */
	/* todo: make case insensitive? */
	/* Get the cookie (code from mod_log_config). */
	if ((cookies = apr_table_get(r->headers_in, "Cookie"))) {
		char *start_cookie, *end_cookie;
		if ((start_cookie = ap_strstr_c(cookies, conf->cookie_auth_cookie))) {
		    start_cookie += strlen(conf->cookie_auth_cookie) + 1;
		    cookie = apr_pstrdup(r->pool, start_cookie);
			/* kill everything in cookie after ';' */
			end_cookie = strchr(cookie, ';');
			if (end_cookie) {
				*end_cookie = '\0';
      }
      ap_unescape_url(cookie);
		}
	}

	/* No cookie? Nothing for us to do. */
	if (!cookie) {
                if (conf->cookie_auth_unauth_redirect) {
        	        const char* redirect = conf->cookie_auth_unauth_redirect;
        		compose_and_set_redirect(r, redirect);
                        return HTTP_MOVED_TEMPORARILY;
                }
                else {
			return DECLINED;
                }
	}

	/* Debug. */
	/*ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	    "%s=%s", conf->cookie_auth_cookie, cookie);*/

	char* aux_auth_info = "";

	/* Construct the fake auth_line. */
	if (conf->cookie_auth_base64) {
		char* decoded_cookie = apr_palloc(r->pool, apr_base64_decode_len(cookie));
    int decoded_cookie_length = apr_base64_decode(decoded_cookie, cookie);

		int valid = 1;

		/* if the cookie is encrypted, decrypt it in place */
		if (conf->cookie_auth_encrypt) {
      MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
      int keysize = strlen(conf->cookie_auth_encrypt);
      int blocksize = mcrypt_enc_get_block_size(td);

			// We will copy the iv from the beginning of the cookie.
			// The iv does not need to be null-terminated, but we will
			// null-terminate it for convenience.
			int iv_length = mcrypt_enc_get_iv_size(td);
			char* iv = (char*) apr_palloc(r->pool, iv_length + 1);
			memcpy(iv, decoded_cookie, iv_length);
			iv[iv_length] = '\0';

			// Take the iv off the beginning of the cookie
			decoded_cookie += iv_length;
      decoded_cookie_length -= iv_length;

      mcrypt_generic_init( td, conf->cookie_auth_encrypt, keysize, iv);
      // Encryption in CBC is performed in blocks, so our
      // decryption string will always be an integral number
      // of full blocks.
      char* decrypt_ptr = decoded_cookie;
      while (decoded_cookie_length >= blocksize) {
        mdecrypt_generic(td, decrypt_ptr, blocksize);
        decrypt_ptr += blocksize;
        decoded_cookie_length -= blocksize;
      }
      if (decoded_cookie_length != 0) {
        valid = 0;
      }
      mcrypt_generic_deinit (td);
      mcrypt_module_close(td);
      /*ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
        "mdecrypt(%s)=%s", conf->cookie_auth_cookie, decoded_cookie);*/
		}

		/* if the cookie did not decrypt, then do nothing */
		if (valid) {
			char* end_auth_info = strchr(decoded_cookie, '\t');

			if (end_auth_info) {
				aux_auth_info = decoded_cookie;
				char* unencoded_cookie = end_auth_info + 1;
				*end_auth_info = 0;

				auth_line = apr_pstrcat(r->pool, "Basic ", ap_pbase64encode(r->pool, unencoded_cookie), NULL);
			}
			else {
				auth_line = apr_pstrcat(r->pool, "Basic ", ap_pbase64encode(r->pool, decoded_cookie), NULL);
			}
		}
	} else {
		// Aux auth info and cookie encrypt features only available in base64 mode
		ap_unescape_url(cookie);
		auth_line = apr_pstrcat(r->pool, "Basic ",
			ap_pbase64encode(r->pool, cookie), NULL);
	}

	/* If there is aux auth info, then set the env variable */
	if (conf->cookie_auth_env) {
	  apr_table_set(r->subprocess_env, conf->cookie_auth_env, aux_auth_info);
	}

	/* Debug. */
	/*ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"Authorization: %s", auth_line);*/

	/* If there is no aux auth info, then force a redirect if our conf directives say that we should */
        if (conf->cookie_auth_env_redirect && !strlen(aux_auth_info)) {
        	const char* redirect = conf->cookie_auth_env_redirect;
        	compose_and_set_redirect(r, redirect);
                return HTTP_MOVED_TEMPORARILY;
        }
        else {
	        /* Set fake auth_line. */
		if (auth_line) {
                	apr_table_set(r->headers_in, "Authorization", auth_line);
                }
	}

	/* Always return DECLINED because we don't authorize, */
	/* we just set things up for the next auth module to. */
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    /* Hook in before the other auth modules. */
    ap_hook_check_user_id(check_auth_cookie, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA auth_cookie_module =
{
    STANDARD20_MODULE_STUFF,
    create_cookie_auth_dir_config, /* per-directory config creator */
    NULL,                          /* dir config merger */
    NULL,                          /* server config creator */
    NULL,                          /* server config merger */
    cookie_auth_cmds,              /* command table */
    register_hooks                 /* set up other request processing hooks */
};


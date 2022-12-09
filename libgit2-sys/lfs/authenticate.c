#include "git2/sys/features.h"
#include "authenticate.h"
#include "git2/cert.h"
#include "git2/remote.h"
#include "git2/sys/credential.h"
#ifdef GIT_SSH
#include <libssh2.h>
#endif
//@see ssh.c
#include "../libgit2/src/util/net.h"
#include "git2/sys/stream.h"
#include "streams/socket.h"

#ifdef GIT_SSH
static int __list_auth_methods(int *out, LIBSSH2_SESSION *session, const char *username);

static void __ssh_error(LIBSSH2_SESSION *session, const char *errmsg)
{
	char *ssherr;
	libssh2_session_last_error(session, &ssherr, NULL, 0);

	git_error_set(GIT_ERROR_SSH, "%s: %s", errmsg, ssherr);
}

static int __request_creds(git_credential **out, git_remote_callbacks *t, const char* url, const char *user, int auth_methods);
static int __git_ssh_authenticate_session(LIBSSH2_SESSION *session,	git_credential *cred);
static int __ssh_channel_read(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel, char* buffer, size_t size);
#endif

int git_lfs_authenticate(const char* url, git_remote_callbacks *t, git_lfs_command_t command, char* buffer, size_t size)
{
#ifdef GIT_SSH
	git_credential *cred = NULL;
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_CHANNEL *channel = NULL;
	int auth_methods, error = 0, rc = 0;
    git_net_url repo_url;
    git_socket_stream* gs = NULL;
	if (git_net_str_is_url(url))
		error = git_net_url_parse(&repo_url, url);
	else
		error = git_net_url_parse_scp(&repo_url, url);
	if ((error = git_socket_stream_new((git_stream**)&gs, repo_url.host, repo_url.port)) < 0 ||
	    (error = git_stream_connect(&gs->parent)) < 0)
		goto done;

    session = libssh2_session_init();
	do {
		error = libssh2_session_handshake(session, gs->s);
	} while (LIBSSH2_ERROR_EAGAIN == error || LIBSSH2_ERROR_TIMEOUT == error);

	if (error != LIBSSH2_ERROR_NONE) {
		__ssh_error(session, "failed to start SSH session");
		libssh2_session_free(session);
		return -1;
	}

	libssh2_session_set_blocking(session, 1);

    git_cert_hostkey cert = {{ 0 }}, *cert_ptr;
    const char *key;
    size_t cert_len;
    int cert_type;

    key = libssh2_session_hostkey(session, &cert_len, &cert_type);
    if (key != NULL) {
        cert.type |= GIT_CERT_SSH_RAW;
        cert.hostkey = key;
        cert.hostkey_len = cert_len;
        switch (cert_type) {
            case LIBSSH2_HOSTKEY_TYPE_RSA:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_RSA;
                break;
            case LIBSSH2_HOSTKEY_TYPE_DSS:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_DSS;
                break;

#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_256
            case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_KEY_ECDSA_256;
                break;
            case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_KEY_ECDSA_384;
                break;
            case LIBSSH2_KNOWNHOST_KEY_ECDSA_521:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_KEY_ECDSA_521;
                break;
#endif

#ifdef LIBSSH2_HOSTKEY_TYPE_ED25519
            case LIBSSH2_HOSTKEY_TYPE_ED25519:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_KEY_ED25519;
                break;
#endif
            default:
                cert.raw_type = GIT_CERT_SSH_RAW_TYPE_UNKNOWN;
        }
    }
#ifdef LIBSSH2_HOSTKEY_HASH_SHA256
    key = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (key != NULL) {
        cert.type |= GIT_CERT_SSH_SHA256;
        memcpy(&cert.hash_sha256, key, 32);
    }
#endif

    key = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    if (key != NULL) {
        cert.type |= GIT_CERT_SSH_SHA1;
        memcpy(&cert.hash_sha1, key, 20);
    }

    key = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    if (key != NULL) {
        cert.type |= GIT_CERT_SSH_MD5;
        memcpy(&cert.hash_md5, key, 16);
    }

    if (cert.type == 0) {
        git_error_set(GIT_ERROR_SSH, "unable to get the host key");
        error = -1;
        goto done;
    }

    /* We don't currently trust any hostkeys */
    git_error_clear();
    
    cert_ptr = &cert;

	if (t->certificate_check) {
		error = t->certificate_check(
			(git_cert *)cert_ptr,
			0,
			repo_url.host,
			t->payload);

		if (error < 0 && error != GIT_PASSTHROUGH) {
			if (!git_error_last())
				git_error_set(GIT_ERROR_NET, "user cancelled hostkey check");

			goto done;
		}
	}
	
	/* we need the username to ask for auth methods */
	if (!repo_url.username) {
		if ((error = __request_creds(&cred, t, repo_url.host, NULL, GIT_CREDENTIAL_USERNAME)) < 0)
			goto done;

		repo_url.username = git__strdup(((git_credential_username *) cred)->username);
		cred->free(cred);
		cred = NULL;
		if (!repo_url.username)
			goto done;
	} else if (repo_url.username && repo_url.password) {
		if ((error = git_credential_userpass_plaintext_new(&cred, repo_url.username, repo_url.password)) < 0)
			goto done;
	}

	if ((error = __list_auth_methods(&auth_methods, session, repo_url.username)) < 0)
		goto done;

	error = GIT_EAUTH;
	/* if we already have something to try */
	if (cred && auth_methods & cred->credtype)
		error = __git_ssh_authenticate_session(session, cred);

	while (error == GIT_EAUTH) {
		if (cred) {
			cred->free(cred);
			cred = NULL;
		}

		if ((error = __request_creds(&cred, t, repo_url.host, repo_url.username, auth_methods)) < 0)
			goto done;

		if (strcmp(repo_url.username, git_credential_get_username(cred))) {
			git_error_set(GIT_ERROR_SSH, "username does not match previous request");
			error = -1;
			goto done;
		}

		error = __git_ssh_authenticate_session(session, cred);

		if (error == GIT_EAUTH) {
			/* refresh auth methods */
			if ((error = __list_auth_methods(&auth_methods, session, repo_url.username)) < 0)
				goto done;
			else
				error = GIT_EAUTH;
		}
	}

	if (error < 0)
		goto done;

	channel = libssh2_channel_open_session(session);
	if (!channel) {
		error = -1;
		__ssh_error(session, "Failed to open SSH channel");
		goto done;
	}

	libssh2_channel_set_blocking(channel, 1);

// Exec commands here
	git_str request = GIT_STR_INIT;
	const char *repo;
	repo = repo_url.path;
	git_str_puts(&request, "git-lfs-authenticate");
	git_str_puts(&request, " ");
	git_str_puts(&request, repo);
	git_str_puts(&request, " ");
	if (command == git_lfs_command_download)
	{
		git_str_puts(&request, "download");
	}
	else if (command == git_lfs_command_upload)
	{
		git_str_puts(&request, "upload");
	}
	error = libssh2_channel_exec(channel, request.ptr);
	git_str_dispose(&request);

	if (error < LIBSSH2_ERROR_NONE) {
		__ssh_error(session, "SSH could not execute request");
		goto done;
	}

    rc = __ssh_channel_read(session, channel, buffer, size);

done:
    if (channel) {
		libssh2_channel_close(channel);
		libssh2_channel_free(channel);
    }

    if (session) {
		libssh2_session_disconnect(session, "closing transport");
		libssh2_session_free(session);
    }

    if (gs) {
		git_stream_close(&gs->parent);
		git_stream_free(&gs->parent);
    }	
    git_net_url_dispose(&repo_url);

	return rc;
#else

#endif
    return 0;
}

#ifdef GIT_SSH
int __request_creds(git_credential **out, git_remote_callbacks *t, const char* url, const char *user, int auth_methods)
{
	int error, no_callback = 0;
	git_credential *cred = NULL;

	if (!t->credentials) {
		no_callback = 1;
	} else {
		error = t->credentials(
			&cred,
            url,
			user,
			auth_methods,
			t->payload);

		if (error == GIT_PASSTHROUGH) {
			no_callback = 1;
		} else if (error < 0) {
			return error;
		} else if (!cred) {
			git_error_set(GIT_ERROR_SSH, "callback failed to initialize SSH credentials");
			return -1;
		}
	}

	if (no_callback) {
		git_error_set(GIT_ERROR_SSH, "authentication required but no callback set");
		return GIT_EAUTH;
	}

	if (!(cred->credtype & auth_methods)) {
		cred->free(cred);
		git_error_set(GIT_ERROR_SSH, "authentication callback returned unsupported credentials type");
		return GIT_EAUTH;
	}

	*out = cred;

	return 0;
}

static int __ssh_agent_auth(LIBSSH2_SESSION *session, git_credential_ssh_key *c) {
	int rc = LIBSSH2_ERROR_NONE;

	struct libssh2_agent_publickey *curr, *prev = NULL;

	LIBSSH2_AGENT *agent = libssh2_agent_init(session);

	if (agent == NULL)
		return -1;

	rc = libssh2_agent_connect(agent);

	if (rc != LIBSSH2_ERROR_NONE)
		goto shutdown;

	rc = libssh2_agent_list_identities(agent);

	if (rc != LIBSSH2_ERROR_NONE)
		goto shutdown;

	while (1) {
		rc = libssh2_agent_get_identity(agent, &curr, prev);

		if (rc < 0)
			goto shutdown;

		/* rc is set to 1 whenever the ssh agent ran out of keys to check.
		 * Set the error code to authentication failure rather than erroring
		 * out with an untranslatable error code.
		 */
		if (rc == 1) {
			rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
			goto shutdown;
		}

		rc = libssh2_agent_userauth(agent, c->username, curr);

		if (rc == 0)
			break;

		prev = curr;
	}

shutdown:

	if (rc != LIBSSH2_ERROR_NONE)
		__ssh_error(session, "error authenticating");

	libssh2_agent_disconnect(agent);
	libssh2_agent_free(agent);

	return rc;
}

#define SSH_AUTH_PUBLICKEY "publickey"
#define SSH_AUTH_PASSWORD "password"
#define SSH_AUTH_KEYBOARD_INTERACTIVE "keyboard-interactive"

int __list_auth_methods(int *out, LIBSSH2_SESSION *session, const char *username)
{
	const char *list, *ptr;

	*out = 0;

	list = libssh2_userauth_list(session, username, strlen(username));

	/* either error, or the remote accepts NONE auth, which is bizarre, let's punt */
	if (list == NULL && !libssh2_userauth_authenticated(session)) {
		__ssh_error(session, "Failed to retrieve list of SSH authentication methods");
		return GIT_EAUTH;
	}

	ptr = list;
	while (ptr) {
		if (*ptr == ',')
			ptr++;

		if (!git__prefixcmp(ptr, SSH_AUTH_PUBLICKEY)) {
			*out |= GIT_CREDENTIAL_SSH_KEY;
			*out |= GIT_CREDENTIAL_SSH_CUSTOM;
#ifdef GIT_SSH_MEMORY_CREDENTIALS
			*out |= GIT_CREDENTIAL_SSH_MEMORY;
#endif
			ptr += strlen(SSH_AUTH_PUBLICKEY);
			continue;
		}

		if (!git__prefixcmp(ptr, SSH_AUTH_PASSWORD)) {
			*out |= GIT_CREDENTIAL_USERPASS_PLAINTEXT;
			ptr += strlen(SSH_AUTH_PASSWORD);
			continue;
		}

		if (!git__prefixcmp(ptr, SSH_AUTH_KEYBOARD_INTERACTIVE)) {
			*out |= GIT_CREDENTIAL_SSH_INTERACTIVE;
			ptr += strlen(SSH_AUTH_KEYBOARD_INTERACTIVE);
			continue;
		}

		/* Skip it if we don't know it */
		ptr = strchr(ptr, ',');
	}

	return 0;
}
int __git_ssh_authenticate_session(
	LIBSSH2_SESSION *session,
	git_credential *cred)
{
	int rc;

	do {
		git_error_clear();
		switch (cred->credtype) {
		case GIT_CREDENTIAL_USERPASS_PLAINTEXT: {
			git_credential_userpass_plaintext *c = (git_credential_userpass_plaintext *)cred;
			rc = libssh2_userauth_password(session, c->username, c->password);
			break;
		}
		case GIT_CREDENTIAL_SSH_KEY: {
			git_credential_ssh_key *c = (git_credential_ssh_key *)cred;

			if (c->privatekey)
				rc = libssh2_userauth_publickey_fromfile(
					session, c->username, c->publickey,
					c->privatekey, c->passphrase);
			else
				rc = __ssh_agent_auth(session, c);

			break;
		}
		case GIT_CREDENTIAL_SSH_CUSTOM: {
			git_credential_ssh_custom *c = (git_credential_ssh_custom *)cred;

			rc = libssh2_userauth_publickey(
				session, c->username, (const unsigned char *)c->publickey,
				c->publickey_len, c->sign_callback, &c->payload);
			break;
		}
		case GIT_CREDENTIAL_SSH_INTERACTIVE: {
			void **abstract = libssh2_session_abstract(session);
			git_credential_ssh_interactive *c = (git_credential_ssh_interactive *)cred;

			/* ideally, we should be able to set this by calling
			 * libssh2_session_init_ex() instead of libssh2_session_init().
			 * libssh2's API is inconsistent here i.e. libssh2_userauth_publickey()
			 * allows you to pass the `abstract` as part of the call, whereas
			 * libssh2_userauth_keyboard_interactive() does not!
			 *
			 * The only way to set the `abstract` pointer is by calling
			 * libssh2_session_abstract(), which will replace the existing
			 * pointer as is done below. This is safe for now (at time of writing),
			 * but may not be valid in future.
			 */
			*abstract = c->payload;

			rc = libssh2_userauth_keyboard_interactive(
				session, c->username, c->prompt_callback);
			break;
		}
#ifdef GIT_SSH_MEMORY_CREDENTIALS
		case GIT_CREDENTIAL_SSH_MEMORY: {
			git_credential_ssh_key *c = (git_credential_ssh_key *)cred;

			GIT_ASSERT(c->username);
			GIT_ASSERT(c->privatekey);

			rc = libssh2_userauth_publickey_frommemory(
				session,
				c->username,
				strlen(c->username),
				c->publickey,
				c->publickey ? strlen(c->publickey) : 0,
				c->privatekey,
				strlen(c->privatekey),
				c->passphrase);
			break;
		}
#endif
		default:
			rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
		}
	} while (LIBSSH2_ERROR_EAGAIN == rc || LIBSSH2_ERROR_TIMEOUT == rc);

	if (rc == LIBSSH2_ERROR_PASSWORD_EXPIRED ||
		rc == LIBSSH2_ERROR_AUTHENTICATION_FAILED ||
		rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED)
			return GIT_EAUTH;

	if (rc != LIBSSH2_ERROR_NONE) {
		if (!git_error_last())
			__ssh_error(session, "Failed to authenticate SSH session");
		return -1;
	}

	return 0;
}
int __ssh_channel_read(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel, char* buffer, size_t size) {
    int rc = 0;
	if ((rc = libssh2_channel_read(channel, buffer, size)) < LIBSSH2_ERROR_NONE) {
		__ssh_error(session, "SSH could not read data");
		return -1;
	}

	/*
	 * If we can't get anything out of stdout, it's typically a
	 * not-found error, so read from stderr and signal EOF on
	 * stderr.
	 */
	if (rc == 0) {
		if ((rc = libssh2_channel_read_stderr(channel, buffer, size)) > 0) {
			git_error_set(GIT_ERROR_SSH, "%*s", rc, buffer);
			return GIT_EEOF;
		} else if (rc < LIBSSH2_ERROR_NONE) {
			__ssh_error(session, "SSH could not read stderr");
			return -1;
		}
	}
    return rc;
}
#endif
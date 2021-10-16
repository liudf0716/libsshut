/* libsshut - ssh async client library */
/* Copyright (c) 2014 Laurent Ghigonis <laurent@gouloum.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event.h>

#include "sshut.h"

static void _cb_state(struct bufferevent *, short , void *);
static void _cb_read(struct bufferevent *, void*);
static int waitsocket(int , LIBSSH2_SESSION *);

struct sshut *
sshut_new(struct event_base *evb, char *ip, int port, struct sshut_auth *auth, enum sshut_reconnect reconnect, int verbose,
	void (*cbusr_connect)(struct sshut *, void *),
	void (*cbusr_disconnect)(struct sshut *, enum sshut_error, void *), void *arg)
{
	struct sshut *ssh;

	if (libssh2_init(0))
		return NULL;

	ssh = calloc(1, sizeof(struct sshut));
	ssh->evb = evb;
	ssh->state = SSHUT_STATE_UNINITIALIZED;
	ssh->conf.ip = strdup(ip);
	ssh->conf.port = port;
	ssh->conf.auth = auth;
	ssh->conf.reconnect = reconnect;
	ssh->conf.verbose = verbose;
	ssh->cbusr_connect = cbusr_connect;
	ssh->cbusr_disconnect = cbusr_disconnect;
	ssh->cbusr_arg = arg;
	sshut_connect(ssh);

	return ssh;
}

void
sshut_free(struct sshut *ssh)
{
	bufferevent_free(ssh->conn.b_ssh);
	free(ssh->conf.ip);	
	free(ssh);
}

int
sshut_connect(struct sshut *ssh)
{
	unsigned long hostaddr;
	struct sockaddr_in sin;
	
	ssh->state = SSHUT_STATE_CONNECTING_SOCKET;
	
	ssh->conn.b_ssh = bufferevent_socket_new(ssh->evb, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(ssh->conn.b_ssh, NULL, NULL, _cb_state, ssh);
	bufferevent_enable(ssh->conn.b_ssh, EV_READ|EV_WRITE);
	
	
	hostaddr = inet_addr(ssh->conf.ip);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(ssh->conf.port);
	sin.sin_addr.s_addr = hostaddr;
	// XXX async connect
	if (bufferevent_socket_connect(ssh->conn.b_ssh, (struct sockaddr*)(&sin),
				sizeof(struct sockaddr_in))) {
		sshut_disconnect(ssh, SSHUT_ERROR_CONNECTION);
		return -1;
	}
	
	ssh->conn.session = libssh2_session_init();
	libssh2_session_set_blocking(ssh->conn.session, 0);
	
	return 0;
}

void
sshut_disconnect(struct sshut *ssh, enum sshut_error error)
{
	bufferevent_free(ssh->conn.b_ssh);
	ssh->cbusr_disconnect(ssh, error, ssh->cbusr_arg);
}

void
sshut_err_print(enum sshut_error error)
{
	printf("sshut error: %d\n", error);
}

static void
_cb_state(struct bufferevent *bev, short event, void *arg)
{
	struct sshut *ssh = (struct sshut *)arg;
	struct sshut_creds *creds = NULL;
	LIBSSH2_CHANNEL *channel;
	int sock = bufferevent_getfd(bev);
	int rc;
	
	/* ... start it up. This will trade welcome banners, exchange keys,
     	 * and setup crypto, compression, and MAC layers
     	 */
    	while((rc = libssh2_session_handshake(ssh->conn.session, sock)) ==
	   LIBSSH2_ERROR_EAGAIN);
    	if(rc) {
		fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
		return;
    	}
	
	creds = ssh->conn.creds_cur;
	if (!creds) {
		creds = sshut_auth_getcreds(ssh->conf.auth);
		if (!creds) {
			fprintf(stderr, "Failure get auth creds\n");
			sshut_disconnect(ssh, SSHUT_ERROR_AUTHENTICATION);
			return;
		}
	}
	
	/* We could authenticate via password */
        while((rc = libssh2_userauth_password(ssh->conn.session, creds->dat.userpass.user, creds->dat.userpass.pass)) ==
               LIBSSH2_ERROR_EAGAIN);
        if(rc) {
            	fprintf(stderr, "Authentication by password failed.\n");
            	return;
        }
	
	if (ssh->conf.verbose)
		libssh2_trace(ssh->conn.session, LIBSSH2_TRACE_KEX|LIBSSH2_TRACE_AUTH);
	
	/* Exec non-blocking on the remove host */
    	while((channel = libssh2_channel_open_session(ssh->conn.session)) == NULL &&
          	libssh2_session_last_error(ssh->conn.session, NULL, NULL, 0) ==
          	LIBSSH2_ERROR_EAGAIN) {
        	waitsocket(sock, ssh->conn.session);
    	}
	
	bufferevent_setcb(ssh->conn.b_ssh, _cb_read, NULL, NULL, ssh);
	bufferevent_enable(ssh->conn.b_ssh, EV_READ|EV_WRITE);
	printf("_cb_state finished\n");
}

static void 
_cb_read(struct bufferevent* bev, void* arg)
{
	struct sshut *ssh = (struct sshut *)arg;
	ssh->cbusr_connect(ssh, ssh->cbusr_arg);
}

static int 
waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

#include <stdio.h>
#include <stdlib.h>
#include <event.h>
#include "sshut.h"

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
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

static void
_cb_exec(struct sshut_action *action, enum sshut_error error, char *cmd, char *output, int output_len, void *arg)
{
	if (error != SSHUT_NOERROR)
		sshut_err_print(error);
	else {
		printf("> %s\n", cmd);
		printf("%s\n", output);
	}
	event_base_loopbreak(action->ssh->evb);
}

static void
_cb_connect(struct sshut *ssh, void *arg)
{
	LIBSSH2_CHANNEL *channel = ssh->channel;
	int rc;
	int sock = bufferevent_getfd(ssh->conn.b_ssh);
	
	if (channel == NULL) {
		printf("channel is NULL !\n");
		return;
	}
	
	printf("exec uname -a\n");
    	while((rc = libssh2_channel_exec(channel, "uname -a")) ==
           LIBSSH2_ERROR_EAGAIN) {
        	waitsocket(sock, ssh->conn.session);
    	}
    	if(rc != 0) {
        	fprintf(stderr, "Error\n");
        	exit(1);
    	}
	
	printf("read ssh response here\n");
	for(;;) {
        	/* loop until we block */
        	int rc;
        	do {
			char buffer[0x4000];
			rc = libssh2_channel_read(channel, buffer, sizeof(buffer) );
			if(rc > 0) {
				int i;
				fprintf(stderr, "We read:\n");
				for(i = 0; i < rc; ++i)
					fputc(buffer[i], stderr);
				fprintf(stderr, "\n");
			} else {
				if(rc != LIBSSH2_ERROR_EAGAIN)
					/* no need to output this for the EAGAIN case */
					fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
			}
        	} while(rc > 0);
		
		/* this is due to blocking that would occur otherwise so we loop on
           	this condition */
        	if(rc == LIBSSH2_ERROR_EAGAIN) {
            		waitsocket(sock, ssh->conn.session);
        	} else
            		break;
    	}
	
	while((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
        	waitsocket(sock, ssh->conn.session);
	
	libssh2_channel_free(channel);
}

static void
_cb_disconnect(struct sshut *ssh, enum sshut_error error, void *arg)
{
	if (error != SSHUT_NOERROR)
		sshut_err_print(error);
	event_base_loopbreak(ssh->evb);
}

int
main(int argc, char **argv)
{
	struct event_base *evb;
	struct sshut_auth *auth;
	struct sshut *ssh;
	
	if (argc != 4) {
		printf("sshut_debug user password port\n");
		return 0;
	}
	
	evb = event_base_new();

	auth = sshut_auth_new();
	sshut_auth_add_userpass(auth, argv[1], argv[2]);
	ssh = sshut_new(evb, "127.0.0.1", atoi(argv[3]), auth, SSHUT_NORECONNECT, SSHUT_NOVERBOSE,
		_cb_connect, _cb_disconnect, NULL);
	event_base_dispatch(evb);

	sshut_auth_free(auth);
	sshut_free(ssh);
	return 0;
}

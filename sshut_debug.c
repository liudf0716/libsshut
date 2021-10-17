#include <stdio.h>
#include <stdlib.h>
#include <event.h>
#include "sshut.h"


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
	
	printf("read ssh response here\n");
	
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
	} while(rc == LIBSSH2_ERROR_EAGAIN);
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

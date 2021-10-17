#include <stdio.h>
#include <stdlib.h>
#include <event.h>
#include <event2/dns.h>

#include "sshut.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

static void _ws_2_ssh(struct evbuffer* , struct sshut* );
static void _cb_ws_recv(struct bufferevent* , void* );
static void _cb_ws_event(struct bufferevent*, short , void*);
static void _ws_request(struct bufferevent*, const char *, const short , const char *, const char *);

struct evdns_base 	*dns_base;
struct bufferevent 	*b_ws;

const char* fixed_key = "dGhlIHNhbXBsZSBub25jZQ==";
const char* fixed_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const char* uri = "/ws/sshproxy";
const char* ws_host = "106.13.23.50";
const short ws_port = 8001;

static void 
_ws_2_ssh(struct evbuffer* buf, struct sshut* ssh)
{
	size_t data_len = evbuffer_get_length(buf);
	printf("receive data_len %d\n", data_len);
	if(data_len < 2)
		return;

	unsigned char* data = evbuffer_pullup(buf, data_len);

	int fin = !!(*data & 0x80);
	int opcode = *data & 0x0F;
	int mask = !!(*(data+1) & 0x80);
	uint64_t payload_len =  *(data+1) & 0x7F;

	size_t header_len = 2 + (mask ? 4 : 0);
	
	if(payload_len < 126){
		if(header_len > data_len)
			return;
	}else if(payload_len == 126){
		header_len += 2;
		if(header_len > data_len)
			return;
		payload_len = ntohs(*(uint16_t*)(data+2));
	}else if(payload_len == 127){
		header_len += 8;
		if(header_len > data_len)
			return;
		payload_len = ntohll(*(uint64_t*)(data+2));
	}

	if(header_len + payload_len > data_len)
		return;

	const unsigned char* mask_key = data + header_len - 4;
	printf("data_len %u mask %x head_len %d payload_len %ld opcode %x\n",
		  data_len, mask, header_len, payload_len, opcode);
	for(int i = 0; mask && i < payload_len; i++)
		data[header_len + i] ^= mask_key[i%4];

	if(opcode == 0x01) {
		printf("receive ws text data\n");
		libssh2_channel_write(ssh->conn.channel, data + header_len, payload_len);
	} else if (opcode == 0x02) {
		printf("receive ws bin data\n");
		libssh2_channel_write(ssh->conn.channel, data + header_len, payload_len);
	}else if(!fin){
		printf("frame to be continue...\n");
		evbuffer_drain(buf, header_len + payload_len);
		return;
	}

	evbuffer_drain(buf, header_len + payload_len);

	//next frame
	_ws_2_ssh(buf, ssh);
}

static void 
_ws_request(struct bufferevent* bev, const char *ws_host, const short ws_port, const char *fixed_key, const char *uri){
	struct evbuffer *out = bufferevent_get_output(bev);
	evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n", uri);
	evbuffer_add_printf(out, "Host:%s:%d\r\n",ws_host, ws_port);
	evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", fixed_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
	evbuffer_add_printf(out, "Origin:http://%s:%d\r\n", ws_host, ws_port); //missing this key will lead to 403 response.

	evbuffer_add_printf(out, "\r\n");
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

static void 
_cb_ws_recv(struct bufferevent* bev, void* ptr)
{
	static int upgraded = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	
	if(!upgraded){
		int data_len = evbuffer_get_length(input);
		unsigned char* data = evbuffer_pullup(input, data_len);
		if(!strstr((const char*)data, "\r\n\r\n"))
			return;
		if(strncmp((const char*)data, "HTTP/1.1 101", strlen("HTTP/1.1 101")) != 0
				|| !strstr((const char*)data, fixed_accept)){
			printf("ws upgraded failed\n");
		}else{
			//drain 
			evbuffer_drain(input, data_len);
			upgraded = 1;
			printf("ws upgraded success\n");
		}
	}else{
		if (!ptr) {
			return;
		}
		struct sshut *ssh = ptr;
		printf("forward ws frame to ssh server\n");
		_ws_2_ssh(input, ssh);
	}
}

static void 
_cb_ws_event(struct bufferevent* bev, short events, void* ptr)
{
	if(events & BEV_EVENT_CONNECTED){
		printf("ws connected\n");
		_ws_request(bev, ws_host, ws_port, fixed_key, uri);
	}else{
		printf("ws disconnected\n");
	}
}

int
main(int argc, char **argv)
{
	struct event_base *evb;
	struct sshut_auth *auth;
	struct sshut *ssh;
	
	if (argc != 6) {
		printf("sshut_debug user password port wshost wsport\n");
		return 0;
	}
	
	evb = event_base_new();
	dns_base = evdns_base_new(evb, 1);

	auth = sshut_auth_new();
	sshut_auth_add_userpass(auth, argv[1], argv[2]);
	ssh = sshut_new(evb, "127.0.0.1", atoi(argv[3]), auth, SSHUT_NORECONNECT, SSHUT_NOVERBOSE,
		_cb_connect, _cb_disconnect, NULL);
	b_ws = bufferevent_socket_new(evb, -1, BEV_OPT_CLOSE_ON_FREE);
	ssh->conn.b_ws = b_ws;
	
	bufferevent_setcb(b_ws, _cb_ws_recv, NULL, _cb_ws_event, ssh);
	bufferevent_enable(b_ws, EV_READ|EV_WRITE);
	bufferevent_socket_connect_hostname(b_ws, dns_base, AF_INET, argv[4], atoi(argv[5]));
	
	event_base_dispatch(evb);

	sshut_auth_free(auth);
	sshut_free(ssh);
	return 0;
}

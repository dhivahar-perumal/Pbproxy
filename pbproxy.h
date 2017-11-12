#ifndef _pbproxy_h
#define _pbproxy_h

int sock, val , conn_check;

int flags;

bool end;

int opt = 0;
bool server = false;
char *dest = NULL;
char *destport = NULL;
char *listenport = NULL;
char *filename = NULL;
 
void* thread_process(void* proc);

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};


struct struct_connection {
	int sock;
	unsigned int addr_len;
	unsigned char *key;
	struct sockaddr address;
	struct sockaddr_in client_address;
};

struct struct_connection *socket_connection;

struct ctr_state state;
	
unsigned char iv[8];

void set_struct_start(struct ctr_state *state, const unsigned char iv[8]);

void startServer(int sock, struct sockaddr_in *client_address, unsigned char *key);

unsigned char* read_file(char* filename);
 
#endif

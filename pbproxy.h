#ifndef _pbproxy_h
#define _pbproxy_h
 
void* thread_process(void* proc);

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};


struct connection {
	int sock;
	unsigned int addr_len;
	unsigned char *key;
	struct sockaddr address;
	struct sockaddr_in client_address;
};

void init_ctr(struct ctr_state *state, const unsigned char iv[8]);

void startServer(int sock, struct sockaddr_in *client_address, unsigned char *key);

unsigned char* read_file(char* filename);
 
#endif

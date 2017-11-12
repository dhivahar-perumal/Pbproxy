#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdbool.h>
#include "pbproxy.h"

#define SIZE 4096

void memcopy_fn(void *dest, void *src, size_t n)
{
   char *csrc = (char *)src;
   char *cdest = (char *)dest;
 
   for (int i=0; i<n; i++)
       cdest[i] = csrc[i];
}

void* thread_process(void* proc) {
	
	/* The thread process created as a process of the pthread_create 
	   It receives a single struct of type struct_connection      */

	if (proc) {

	/* initialising the struct for establishing the connection */

	socket_connection = (struct struct_connection *)proc;

	/* A buffer is set for communicating with the requests between the processes */

	unsigned char buf[SIZE];
	
	AES_KEY aes_key;

	/* The end of file descriptor is handled by this variable */

	end = false;

	/*  Getting a socket to start communcating */

	sock = socket(AF_INET, SOCK_STREAM, 0);

	conn_check = connect(sock, (struct sockaddr *)&socket_connection->client_address, sizeof(socket_connection->client_address));	
	
	/*  Handling the connection error when the connect() returns a value of -1 */

	if (conn_check == -1) {
		printf("SSH Connection failed\n");
		printf("The connect returned a value of %d\n",conn_check);
	
	/*  Exiting the thread on failure*/

		pthread_exit(0);

	}
	else 
	{
		printf("SSH Connection Successful\n");	
	}
	

	flags = fcntl(socket_connection->sock, F_GETFL);

	
	if (flags == -1) {

		/* Closing the connection */		
				
		close(socket_connection->sock);
		close(sock);

		printf("The socket connections are closed");

		free(socket_connection);

		printf("The flags returned error with a value of %d\n",flags);		
				
		/*  Exiting the thread on failure */		

		pthread_exit(0);
	}


	fcntl(socket_connection->sock, F_SETFL, flags | O_NONBLOCK);
	
	flags = fcntl(sock, F_GETFL);

	if (flags == -1 ) {
		
		/*  Exiting the thread on failure */

		pthread_exit(0);
	}

	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

		/* AES encryption key set */

	if (AES_set_encrypt_key(socket_connection->key, 128, &aes_key) < 0) {
		
		/*  Exiting here on failure */

		exit(1);
	}

	while (1) {

		/*  Reading from the ssh fd */

		while ((val = read(sock, buf, SIZE)) > 0) {
			if (val > 0) {
				char *temp_buffer = (char*)malloc(val + 8);
								
				unsigned char encr_arr[val];

				RAND_bytes(iv, 8);

				//memcpy(temp_buffer, iv, 8);
				char *d = temp_buffer;
  				const char *s = iv;
				int len = 8;
  				while (len--)
    				*d++ = *s++;

		/*  Setting num and ecount to zero */

				set_struct_start(&state, iv);
		
		/*  Encryption part  */

				AES_ctr128_encrypt(buf, encr_arr, val, &aes_key, state.ivec, state.ecount, &state.num);
				
				memcpy(temp_buffer + 8, encr_arr, val);
				
				write(socket_connection->sock, temp_buffer, val + 8);
				
				free(temp_buffer);
			}

			if (end == false && val == 0)
				end = true;

			if (val < SIZE)
				break;
		}

		while ((val = read(socket_connection->sock, buf, SIZE)) > 0) {

			unsigned char decr[val - 8];

			if (val < 8) {
				
				close(socket_connection->sock);
				close(sock);
				free(socket_connection);
				
		/*  Closing the connection and exiting  */

				printf("Freeing connection \n");

				pthread_exit(0);
			}

			// memcpy(iv, buf, 8);
			char *dm = iv;
  			const char *sm = buf;
			int leng = 8;
  			while (leng--)
    			*dm++ = *sm++;

		/*  Setting num and ecount to zero */

			set_struct_start(&state, iv);

			AES_ctr128_encrypt(buf + 8, decr, val - 8, &aes_key, state.ivec, state.ecount, &state.num);
			write(sock, decr, val - 8);

			if (val < SIZE)
				break;
		};

		if (end)
			break;
	}

	close(socket_connection->sock);
	close(sock);
	free(socket_connection);
	pthread_exit(0);
	}
	else
	{
		printf("closing due to failure\n");
		pthread_exit(0);
	}
}


void set_struct_start(struct ctr_state *state, const unsigned char iv[8]) {
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	 * first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

void startServer(int sock, struct sockaddr_in *client_address, unsigned char *key) {
	struct struct_connection *connection;
	pthread_t thread;

	connection = (struct struct_connection *)malloc(sizeof(struct struct_connection));
	connection->sock = accept(sock, &connection->address, &connection->addr_len);
	if (connection->sock > 0) {
		connection->client_address = *client_address;
		connection->key = key;
		pthread_create(&thread, 0, thread_process, (void*)connection);
		pthread_detach(thread);
	} else {
		free(connection);
	}
}

unsigned char* read_file(char* filename) {
	unsigned char *buf = 0;
	long len;
	FILE *f = fopen (filename, "rb");

	if (f) {
		fseek (f, 0, SEEK_END);
		len = ftell (f);
		fseek (f, 0, SEEK_SET);
		buf = malloc (len);
		if (buf)
			fread (buf, 1, len, f);
		fclose (f);
	} else
		return 0;

	return buf;
}


int main(int argc, char *argv[]) {
	

	struct hostent *host;
	struct sockaddr_in server_address, client_address;
	bzero(&server_address, sizeof(server_address));
	bzero(&server_address, sizeof(client_address));

	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch (opt) {
		case 'l':
			listenport = optarg;
			server = true;
			break;
		case 'k':
			filename = optarg;
			break;
		default:
			printf("Unknown option\n");
			return 0;
		}
	}

	if (filename == NULL) {
		printf("Key file missing\n");
		return 0;
	}

	if (optind == argc - 2) {
		dest = argv[optind];
		destport = argv[optind + 1];
	} else {
		printf("Provide options properly\n");
		return 0;
	}

	int dport = (int)strtol(destport, NULL, 10);
	if ((host = gethostbyname(dest)) == 0) {
		printf("gethostbyname error\n");
		return 0;
	}

	unsigned char *key = read_file(filename);
	if (!key) {
		printf("read key file failed\n");
		return 0;
	}

	if (server == false) {
		int sock, n;
		char buf[SIZE];

		struct ctr_state state;
		unsigned char iv[8];
		AES_KEY aes_key;

		sock = socket(AF_INET, SOCK_STREAM, 0);

		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(dport);
		server_address.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;

		if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
			printf("Connect failed\n");
			return 0;
		}

		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sock, F_SETFL, O_NONBLOCK);

		if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
			printf("AES_set_encrypt_key error\n");
			exit(1);
		}

		while (1) {
			while ((n = read(sock, buf, SIZE)) > 0) {
				if (n < 8) {
					printf("Packet len < 8\n");
					close(sock);
					return 0;
				}

				memcpy(iv, buf, 8);
				unsigned char decr[n - 8];
				set_struct_start(&state, iv);
				AES_ctr128_encrypt(buf + 8, decr, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

				write(STDOUT_FILENO, decr, n - 8);
				if (n < SIZE)
					break;
			}

			while ((n = read(STDIN_FILENO, buf, SIZE)) > 0) {
				if (!RAND_bytes(iv, 8)) {
					printf("Could not create random bytes\n");
					exit(1);
				}
				char *temp_buffer = (char*)malloc(n + 8);
				memcpy(temp_buffer, iv, 8);

				unsigned char encr[n];
				set_struct_start(&state, iv);
				AES_ctr128_encrypt(buf, encr, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(temp_buffer + 8, encr, n);
				write(sock, temp_buffer, n + 8);
				free(temp_buffer);
				if (n < SIZE)
					break;
			}
		}
	} else {
		int sock;
		int lport = (int)strtol(listenport, NULL, 10);
		sock = socket(AF_INET, SOCK_STREAM, 0);

		client_address.sin_family = AF_INET;
		client_address.sin_port = htons(dport);
		client_address.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;

		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = htons(INADDR_ANY);
		server_address.sin_port = htons(lport);

		bind(sock, (struct sockaddr *)&server_address, sizeof(server_address));

		if (listen(sock, 10) < 0) {
			printf("Listen failed\n");
			return 0;
		};

		while (1) {
			startServer(sock, &client_address, key);
		}
	}
	return 1;
}

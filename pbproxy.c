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
 
/*  tried implementing my own memcopy for some reasons */

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

				
		//copying the values from iv to temp buffer

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

				int valp = val + 8;
				
				write(socket_connection->sock, temp_buffer, valp);
				
				free(temp_buffer);
			}

			if (end == false && val == 0)
				end = true;

			if (val < SIZE)
				break;
		}
		
		/*  read socket for input */

		while ((val = read(socket_connection->sock, buf, SIZE)) > 0) {

			int vald = val - 8;

			unsigned char decr_arr[vald];

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

			int temp_v = val;

			AES_ctr128_encrypt(buf + 8, decr_arr, vald, &aes_key, state.ivec, state.ecount, &state.num);
			
			write(sock, decr_arr, vald);

			if (temp_v < SIZE)
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


void set_struct_start(struct aes_ctr_state *temp_val, const unsigned char iv_val[8]) {
	
	memset(temp_val->ivec + 8, 0, 8);	
	memcpy(temp_val->ivec, iv_val, 8);

	temp_val->num = 0;
	memset(temp_val->ecount, 0, AES_BLOCK_SIZE);
	
}

void startServer(int sock, struct sockaddr_in *c_addr, unsigned char *key) {
	
	/* server start function here */	
	
	pthread_t thread;
	
	int conn_accept_check = 0;

	struct struct_connection *conn;
	
	conn = (struct struct_connection *)malloc(sizeof(struct struct_connection));
	
	/*  Connection accept done here */	

	conn->sock = accept(sock, &conn->address, &conn->addr_len);
	
	if(conn->sock > 0)
		conn_accept_check = 1;
	else
		conn_accept_check = 0;

	if (conn_accept_check == 0) {
		free(conn);		
	} 
	else 
	{

		/*  Initiliazing pthread here */

		conn->key = key;

		conn->client_address = *c_addr;
		
		pthread_create(&thread, 0, thread_process, (void*)conn);
		
		pthread_detach(thread);
		
	}
}

unsigned char * read_key(const char *filename) {

    long int size = 0;
    
    FILE *key = fopen(filename, "r");

    if (!key) {
        fprintf(stderr, "Open error for key file\n");
        return NULL;
    }

    fseek(key, 0, SEEK_END);

    size = ftell(key);

    rewind(key);

    char *res = (char *) malloc(size);

    if (fread(res, 1, size, key) != size) {

        return NULL;
    }

    fclose(key);
    
    return res;
}


int main(int argc, char *argv[]) {
	
	
	/* Socket Structs initialization */
	struct sockaddr_in server_addr, client_addr;

	struct hostent *host;

	int listen_port_check = 0;

	int saddr = sizeof(server_addr);
	int caddr = sizeof(client_addr);

	/* sock connection bzero function */

	bzero(&server_addr, saddr);

	bzero(&server_addr, caddr);

	int file_check = 0;

	/*  getopt implementation for receiving from the command line */	

	while ((optid = getopt(argc, argv, "l:k:")) != -1) 
	{
		switch (optid) {

		case 'k':
			filename = optarg;
			file_check = 1;			
			break;

		case 'l':
			listen_port = optarg;
			listen_port_check = 1;
			s_mode = true;	
			break;
		
		default:
			printf("Only options -l and -k are supported");
			return 0;
		}
	}

	if (file_check == 0) {
		printf("File not provided\n");
		return 0;
	}

	if (optind == argc - 2) {
		dest = argv[optind];
		destport = argv[optind + 1];
	} else {
		printf("Invalid command\n");
		return 0;
	}

	unsigned char *key = read_key(filename);

	if (listen_port_check == 1 )
	{
		printf("Listening at port - %s \n", listen_port); 
	
	}


	
	int d_port = (int)strtol(destport, NULL, 10);

	host = gethostbyname(dest);

	
	

	/*  client Mode allows the below to run */

	if (s_mode == false) {

		

		struct aes_ctr_state state;

		AES_KEY aes_key;

		sock = socket(AF_INET, SOCK_STREAM, 0);

		/*  pulled code from open source - https://web.eecs.umich.edu/~sugih/courses/eecs489/common/notes/sockets.txt 

		    and http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html     			   	   */
		
		unsigned char iv[8];
		
		if(saddr)
		{
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(d_port);
		server_addr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
		}
		else
		{
	
		printf("issues with struct implementation");
		
		}

		int sock, n;
		char buf[SIZE];

		connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sock, F_SETFL, O_NONBLOCK);

		AES_set_encrypt_key(key, 128, &aes_key);


		while (1) {
			while ((n = read(sock, buf, SIZE)) > 0) {
				if (n > 8) {
				
				unsigned char decr_arr[n - 8];				

				char *d_m = iv;

	  			const char *s_m = buf;

				int leng = 8;

	  			while (leng--)
				{
		    			*d_m++ = *s_m++;
				}

				set_struct_start(&state, iv);

				

			/* pulled code from http://openssl.6102.n7.nabble.com/Question-on-how-to-use-AES-128-CTR-td9415.html for AES reference */
				
				AES_ctr128_encrypt(buf + 8, decr_arr, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

				write(STDOUT_FILENO, decr_arr, n - 8);
				if (n < SIZE)
					break;
				}
				else
				{
					printf("Packet len < 8\n");
					close(sock);
					return 0;	
				}
			}

			while ((n = read(STDIN_FILENO, buf, SIZE)) > 0) {

				unsigned char encr[n];

				RAND_bytes(iv, 8);

				char *temp_buffer = (char*)malloc(n + 8);

				
				char *d1m = temp_buffer;
	  			
				const char *s1m = iv;

				int leng1 = 8;

	  			while (leng1--)
				{
	    			*d1m++ = *s1m++;
				}

			/*  pulled code from http://openssl.6102.n7.nabble.com/Question-on-how-to-use-AES-128-CTR-td9415.html for reference */

				

				set_struct_start(&state, iv);

				AES_ctr128_encrypt(buf, encr, n, &aes_key, state.ivec, state.ecount, &state.num);

				memcpy(temp_buffer + 8, encr, n);

				write(sock, temp_buffer, n + 8);

				free(temp_buffer);

				if (n < SIZE)
					break;
			}
		}
	} 
		else {

		/*  Server code resides here */

		int sock;
		
		sock = socket(AF_INET, SOCK_STREAM, 0);

		/*  struct value assigning */

		/*  pulled code from open source reference https://web.eecs.umich.edu/~sugih/courses/eecs489/common/notes/sockets.txt */

		if(caddr)
		{
		client_addr.sin_family = AF_INET;
		client_addr.sin_port = htons(d_port);
		client_addr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
		}
		else
		{
		printf("issue with the structs");
		}

		int lisport = (int)strtol(listen_port, NULL, 10);

		if(saddr)
		{		
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = htons(INADDR_ANY);
		server_addr.sin_port = htons(lisport);
		}
		else
		{
		printf("issue with the structs");
		}

		bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

		int listen_check = listen(sock, 10);
 
		if ( listen_check == -1) {

			return 0;
		};
		
		printf("Initiating pbproxy server\n");
		printf("----------------PBPROXY----------------\n");
		printf("The clients can connect to the server at the post mentioned\n");		

		while (1) {
			startServer(sock, &client_addr, key);
		}

		printf("The server is shutting down");
	}
	return 1;
}

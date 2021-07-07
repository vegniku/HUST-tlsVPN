#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>

#define BUFF_SIZE 2000
/* define HOME to be dir for key and cert files... */
#define HOME	"./mycert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#define client_max 10

int setupTCPServer();	// Defined in Listing 19.10
void processRequest(SSL * ssl, int sockfd,int tunfd);	// Defined in Listing 19.12
int createTunDevice();
void tunSelected(int tunfd, int sockfd, SSL * ssl);
void socketSelected(int tunfd, int sockfd, SSL * ssl);
void check_client(int sockfd);

int main()
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int err;
	int tunfd[client_max];
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection
	ssl = SSL_new(ctx);

	struct sockaddr_in sa_client;
	size_t client_len = sizeof(sa_client);;
	int listen_sock = setupTCPServer();

	fprintf(stderr, "listen_sock = %d\n", listen_sock);

	for (int i = 0; i < client_max; i++)
	{
		int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);

		tunfd[i] = createTunDevice();
		fprintf(stderr, "sock = %d\n", sock);
		if (sock == -1)
		{
			fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			continue;
		}
		if (fork() == 0)
		{ // The child process
			close(listen_sock);

			SSL_set_fd(ssl, sock);
			int err = SSL_accept(ssl);

			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");
			check_client(sock);
			processRequest(ssl, sock, tunfd[i]);
			close(sock);
			return 0;
		}
		else
		{ // The parent process
			close(sock);
		}
	}

	//while (1) {
	//	int sock = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);

	//	fprintf(stderr, "sock = %d\n", sock);
	//	if (sock == -1) {
	//		fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
	//		continue;
	//	}
	//	if (fork() == 0) {	// The child process
	//		close(listen_sock);

	//		SSL_set_fd(ssl, sock);
	//		int err = SSL_accept(ssl);

	//		fprintf(stderr, "SSL_accept return %d\n", err);
	//		CHK_SSL(err);
	//		printf("SSL connection established!\n");

	//		processRequest(ssl, sock);
	//		close(sock);
	//		return 0;
	//	} else {	// The parent process
	//		close(sock);
	//	}
	//}

}
int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}
void tunSelected(int tunfd, int sockfd, SSL* ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	//sendto(sockfd, buff, len, 0, (struct sockaddr*)&peerAddr, sizeof(peerAddr));
	if (len <= 0)
		exit(-1);
	SSL_write(ssl, buff, sizeof(buff) - 1);
}

void socketSelected(int tunfd, int sockfd, SSL* ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	//len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
	len = SSL_read(ssl, buff, sizeof(buff) - 1);
	if (len <= 0)
		exit(-1);
	write(tunfd, buff, len);
}
void check_client(int sockfd)
{
	char username[20], passwd[20];
	recv(sockfd, username, 20, 0);
	recv(sockfd, passwd, 20, 0);

	struct spwd* pw;
	char* epasswd;
	pw = getspnam(username);
	if (pw == NULL)
	{
		send(sockfd, "user not exist!", 20, 0);
		exit(-1);
	}
	printf("Login name: %s\n", pw->sp_namp);
	printf("Passwd : %s\n", pw->sp_pwdp);
	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp))
	{
		send(sockfd, "passwd is wrong!", 20, 0);
		exit(-1);
	}
	send(sockfd, "ok", 20, 0);
}

int setupTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}

void processRequest(SSL * ssl, int sockfd,int tunfd)
{
	while (1)
	{
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet))
			tunSelected(tunfd, sockfd, ssl);
		if (FD_ISSET(sockfd, &readFDSet))
			socketSelected(tunfd, sockfd, ssl);
	}
	//char buf[1024];
	//int len = SSL_read(ssl, buf, sizeof(buf) - 1);

	//buf[len] = '\0';
	//printf("Received: %s\n", buf);

	//// Construct and send the HTML page
	//char *html = "HTTP/1.1 200 OK\r\n" "Content-Type: text/html\r\n\r\n" "<!DOCTYPE html><html>" "<head><title>Hello World</title></head>" "<style>body {background-color: black}" "h1 {font-size:3cm; text-align: center; color: white;" "text-shadow: 0 0 3mm yellow}</style></head>" "<body><h1>Hello, world!</h1></body></html>";

	//SSL_write(ssl, html, strlen(html));
	//SSL
}

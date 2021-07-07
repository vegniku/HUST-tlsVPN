#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./mycert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err, s) if ((err) == -1){perror(s);exit(1);}
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }


#define BUFF_SIZE 2000
#define CA_DIR "ca_client"
int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
		exit(-1);
	}
}
SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if (SSL_CTX_load_verify_locations(ctx, "facert_server/ca.crt", NULL) < 1)
	{
		printf("Error setting the verify locations 1. \n");
		exit(0);
	}
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}
int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1)
	{
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1)
	{
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
int setupTCPClient(const char *hostname, int port)
{
	struct sockaddr_in server_addr;

	// Get the IP address from hostname
	//struct hostent *hp = gethostbyname(hostname);
	struct addrinfo hints, * result;
	hints.ai_family = AF_INET;	   // AF_INET means IPv4 only addresses
	hints.ai_flags = AI_CANONNAME; /* For wildcard IP address */
	hints.ai_protocol = 0;		   /* Any protocol */
	hints.ai_socktype = SOCK_STREAM;
	int error = getaddrinfo(hostname, NULL, &hints, &result);
	if (error)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		exit(1);
	}
	// The result may contain a list of IP address; we take the first one.
	struct sockaddr_in* ip = (struct sockaddr_in*)result->ai_addr;
	printf("IP Address: %s\n", (char*)inet_ntoa(ip->sin_addr));

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, '\0', sizeof(server_addr));
	//memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	server_addr.sin_addr.s_addr = ip->sin_addr.s_addr;
	//server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;
//printf("IP Address: %s\n", (char*)inet_ntoa(server_addr.sin_addr));
	// Connect to the destination
	//connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0)
		printf("connect error\n");
	freeaddrinfo(result);
	return sockfd;
}
void identity_check(int sockfd)
{
	//certify the client
	char username[20], buff[20];
	char* passwd;
	printf("Username:");
	scanf("%s", username);
	send(sockfd, username, 20, 0);
	passwd = getpass("Password : ");
	send(sockfd, passwd, 20, 0);
	recv(sockfd, buff, 20, 0);
	if (strcmp(buff, "ok"))
	{
		printf("%s\n", buff);
		exit(-1);
	}
	printf("login successfully\n");
}
int main(int argc, char *argv[])
{
	int tunfd;
	tunfd = createTunDevice();
	char *hostname = "yahoo.com";
	int port = 4433;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

	/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	identity_check(sockfd);

	/*----------------Send/Receive data --------------------*/
	char buf[9000];
	char sendBuf[200];

	//sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
	//SSL_write(ssl, sendBuf, strlen(sendBuf));

	//int len;

	//do {
	//	len = SSL_read(ssl, buf, sizeof(buf) - 1);
	//	buf[len] = '\0';
	//	printf("%s\n", buf);
	//} while (len > 0);
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

}

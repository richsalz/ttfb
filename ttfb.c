/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * One of the most important perforance metrics on the Web is Time To
 * First Byte (TTFB). It's the measure from when a client sends a request
 * to the server until when the server responds.  This program tries to
 * help measure that.  In order to reduce outside effects, we have one
 * executable that forks into a client and server. We use the loopback
 * address because we know that gets optimized.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/err.h>
#ifdef OPENSSL_30
# include <openssl/provider.h>
#endif
#include <openssl/ssl.h>
#include <openssl/bio.h>

static const char *certfile = "server.pem";
static const char *keyfile;
static SSL_CTX *server_ctx;
static SSL_CTX *client_ctx;

static void failed(const char *what)
{
    fprintf(stderr, "openssl failed %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void xerror(const char *what)
{
    perror(what);
    exit(1);
}

static void client(const char *port, int repeats)
{
    int s;

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        xerror("socket");
    xerror("client exiting");
}

static void server(const char *port, int repeats)
{
    int i;
    BIO *in, *tmp, *ssl_bio;
    char buff[128];

    if (!SSL_CTX_use_certificate_file(server_ctx, certfile, SSL_FILETYPE_PEM))
        failed("SSL_CTX_use_certificate_file");
    if (!SSL_CTX_use_PrivateKey_file(server_ctx, keyfile, SSL_FILETYPE_PEM))
        failed("SSL_CTX_use_PrivateKey_file");
    sprintf(buff, "127.0.0.1:%s", port);
    if ((in = BIO_new_accept(port)) == NULL)
        failed("BIO_new_accept");
    if ((ssl_bio = BIO_new_ssl(server_ctx, 0)) == NULL)
        failed("BIO_new_ssl");

    BIO_set_accept_bios(in, ssl_bio);
    for ( ; ; ) {
        if (BIO_do_accept(in) <= 0)
            failed("BIO_do_accept");
        i = BIO_read(in, buff, sizeof buff);
        if (i < 0)
            failed("server BIO_read");
        BIO_write(in, "TTFB\n", 5);
        tmp = BIO_pop(in);
        BIO_free_all(tmp);
    }

    xerror("server exiting");
}

static void usage(const char *goof)
{
    if (goof != NULL)
        fprintf(stderr, "Usage error: %s\n", goof);
    fprintf(stderr, "Flags:\n");
    fprintf(stderr, " -c file  File with PEM certificate\n");
    fprintf(stderr, " -h       This help message\n");
    fprintf(stderr, " -k file  File with PEM key\n");
    fprintf(stderr, " -l path  Provider to load\n");
    fprintf(stderr, " -p #     Use the port number\n");
    fprintf(stderr, " -q txt   Query string to indicate provider\n");
    fprintf(stderr, " -r #     Number of requests to send\n");
    fprintf(stderr, " -s       Put server in background, not child\n");
    exit(goof == NULL ? 0 : 1);
}

int main(int ac, char **av)
{
    int i;
    int repeats = 1000;
    int server_in_background = 0;
    const char *port = "4433";
    const char *query = NULL;
    const char *load = NULL;
#ifdef OPENSSL_30
    OSSL_PROVIDER *prov;
#endif
    BIO_ADDRINFO *sai;

    /* Parse JCL. */
    while ((i = getopt(ac, av, "c:hk:l:p:q:r:s")) != -1)
        switch (i) {
            default:
                usage("Unknown option");
                /* NOTREACHED */
            case 'c':
                certfile = optarg;
                break;
            case 'h':
                usage(NULL);
                /* NOTREACHED */
            case 'k':
                keyfile = optarg;
                break;
            case 'l':
#ifndef OPENSSL_30
		fprintf(stderr, "Warning: -l option ignored pre-3.0\n");
#endif
                load = optarg;
                break;
            case 'p':
                if (atoi(optarg) <= 0)
                    usage("Bad port number");
                port = optarg;
                break;
            case 'q':
                query = optarg;
#ifndef OPENSSL_30
		fprintf(stderr, "Warning: -q option ignored pre-3.0\n");
#endif
                break;
            case 'r':
                if ((repeats = atoi(optarg)) <= 0)
                    usage("Bad repeat count");
                break;
	    case 's':
		server_in_background = 1;
		break;
        }
    ac -= optind;
    av += optind;
    if (*av != NULL)
        usage("Extra arguments given");

    /* Default is key is in same file as cert. */
    if (keyfile == NULL)
        keyfile = certfile;

    /* If provider given, load it. */
#ifdef OPENSSL_30
    if (load != NULL) {
        prov = OSSL_PROVIDER_load(NULL, load);
        if (prov == NULL) {
            fprintf(stderr,
"Consider using a full path or set OPENSSL_MODULES environment variable\n");
            failed("to load provider");
        }
    }
#endif

    /* Init socket facility. */
    if (BIO_sock_init() != 1)
        failed("to BIO_sock_init");

    /* Create the server and client SSL_CTX */
#ifdef OPENSSL_30
    server_ctx = SSL_CTX_new_ex(NULL, query, TLS_server_method());
#else
    server_ctx = SSL_CTX_new(TLS_server_method());
#endif
    if (server_ctx == NULL)
        failed("to create server_ctx");
#ifdef OPENSSL_30
    client_ctx = SSL_CTX_new_ex(NULL, query, TLS_client_method());
#else
    client_ctx = SSL_CTX_new(TLS_client_method());
#endif
    if (client_ctx == NULL)
        failed("to create client_ctx");

    i = fork();
    if (i < 0) {
        perror("fork");
        failed("fork failed");
    }
    if (i == 0) {
        /* Child; client (or maybe server). */
	if (server_in_background)
	    server(port, repeats);
	else
	    client(port, repeats);
    } else {
        /* Parent; server, so we can CTRL-C it (or maybe not). */
	if (server_in_background)
	    client(port, repeats);
	else
	    server(port, repeats);
    }

    return 0;
}

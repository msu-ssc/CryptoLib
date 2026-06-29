/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
   including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
   of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
   documentation will conform to the program, or any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
   consequential damages, arising out of, resulting from, or in any way connected with the software or its
   documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
   from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

/*******************************************************************************
** Standalone CryptoLib Implementation
** UDP interfaces to apply / process each frame type and return the result.
*******************************************************************************/

#include "lemsa3_standalone.h"

#include <errno.h>
#include <sys/stat.h>

/*
** Global Variables
*/
#define DYNAMIC_LENGTHS 1

static volatile uint8_t keepRunning    = CRYPTO_LIB_SUCCESS;
static volatile uint8_t tc_seq_num     = 0;
static volatile uint8_t tc_vcid        = CRYPTO_STANDALONE_FRAMING_VCID;
static volatile uint8_t tc_debug       = 1;
static volatile uint8_t crypto_use_tcp = STANDALONE_TCP ? 1 : 0;

#define CRYPTO_STANDALONE_TC_SCID             119
#define CRYPTO_STANDALONE_TC_HAS_FECF         TC_HAS_FECF
#define CRYPTO_STANDALONE_TC_HAS_SEGMENT_HDRS TC_NO_SEGMENT_HDRS
#define CRYPTO_STANDALONE_APPLY_STATE_DIR     "standalone_apply_state"

static int32_t crypto_standalone_apply_use_state_dir(void)
{
    if (mkdir(CRYPTO_STANDALONE_APPLY_STATE_DIR, 0775) != 0 && errno != EEXIST)
    {
        perror("mkdir");
        return CRYPTO_LIB_ERROR;
    }

    if (chdir(CRYPTO_STANDALONE_APPLY_STATE_DIR) != 0)
    {
        perror("chdir");
        return CRYPTO_LIB_ERROR;
    }

    return CRYPTO_LIB_SUCCESS;
}

static uint8_t crypto_standalone_vcid_requires_security(uint8_t vcid)
{
    return (vcid == 2 || vcid == 3);
}

static int32_t crypto_standalone_get_tc_vcid(const uint8_t *frame, uint16_t frame_len, uint8_t *vcid)
{
    if (frame_len < TC_FRAME_HEADER_SIZE)
    {
        return CRYPTO_LIB_ERROR;
    }

    *vcid = (frame[2] >> 2) & 0x3F;
    return CRYPTO_LIB_SUCCESS;
}

int32_t crypto_host_to_ip(const char *hostname, char *ip)
{
    struct addrinfo hints, *res, *p;
    int             status;
    void           *addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET; // Uses IPV4 only.  AF_UNSPEC for IPV6 Support
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0)
    {
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr                     = &(ipv4->sin_addr);

        // Convert IP to String
        if (inet_ntop(p->ai_family, addr, ip, INET_ADDRSTRLEN) == NULL)
        {
            freeaddrinfo(res);
            return 1;
        }

        freeaddrinfo(res);
        return 0; // IP Found
    }
    freeaddrinfo(res);
    return 1; // IP NOT Found
}

int32_t crypto_standalone_socket_init(udp_info_t *sock, int32_t port, uint8_t bind_sock, int connection)
{
    int       status = CRYPTO_LIB_SUCCESS;
    int       optval;
    socklen_t optlen;

    sock->port = port;

    if (connection == 1)
    {
        /* Creating TCP socket */
        sock->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        if (sock->sockfd == -1)
        {
            printf("tcp_init: Socket create error on port %d\n", sock->port);
            return CRYPTO_LIB_ERROR;
        }

        /* Determine IP */
        sock->saddr.sin_family = AF_INET;
        if (inet_addr(sock->ip_address) != INADDR_NONE)
        {
            sock->saddr.sin_addr.s_addr = inet_addr(sock->ip_address);
        }
        else
        {
            char ip[16];
            int  check = crypto_host_to_ip(sock->ip_address, ip);
            if (check == 0)
            {
                sock->saddr.sin_addr.s_addr = inet_addr(ip);
            }
            else
            {
                printf("socket_init: Failed to resolve hostname '%s'\n", sock->ip_address);
                return CRYPTO_LIB_ERROR;
            }
        }
        sock->saddr.sin_port = htons(sock->port);
    }
    else
    {
        /* Create UDP socket */
        sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock->sockfd == -1)
        {
            printf("udp_init:  Socket create error port %d \n", sock->port);
        }

        /* Determine IP */
        sock->saddr.sin_family = AF_INET;
        if (inet_addr(sock->ip_address) != INADDR_NONE)
        {
            sock->saddr.sin_addr.s_addr = inet_addr(sock->ip_address);
        }
        else
        {
            char ip[16];
            int  check = crypto_host_to_ip(sock->ip_address, ip);
            if (check == 0)
            {
                sock->saddr.sin_addr.s_addr = inet_addr(ip);
            }
        }
        sock->saddr.sin_port = htons(sock->port);
    }

    if (crypto_use_tcp && sock->port == TC_APPLY_FWD_PORT)
    {
        if (bind_sock != 0)
        {
            // TCP server: bind, listen, accept
            if (bind(sock->sockfd, (struct sockaddr *)&sock->saddr, sizeof(sock->saddr)) != 0)
            {
                printf("tcp_init: Bind failed on port %d\n", sock->port);
                return CRYPTO_LIB_ERROR;
            }

            if (listen(sock->sockfd, 1) != 0)
            {
                printf("tcp_init: Listen failed on port %d\n", sock->port);
                return CRYPTO_LIB_ERROR;
            }

            int clientfd = accept(sock->sockfd, NULL, NULL);
            if (clientfd < 0)
            {
                printf("tcp_init: Accept failed on port %d\n", sock->port);
                return CRYPTO_LIB_ERROR;
            }

            // Replace listener with connected client socket
            // close(sock->sockfd); //may be needed
            sock->sockfd = clientfd;
        }
        else
        {
            // TCP client: connect
            if (connect(sock->sockfd, (struct sockaddr *)&sock->saddr, sizeof(sock->saddr)) < 0)
            {
                printf("tcp_init: Connect failed to %s:%d\n", sock->ip_address, sock->port);
                return CRYPTO_LIB_ERROR;
            }
        }
    }
    else
    {
        // UDP: bind only if needed
        if (bind_sock == 0 && sock->port != TC_APPLY_FWD_PORT)
        {
            status = bind(sock->sockfd, (struct sockaddr *)&sock->saddr, sizeof(sock->saddr));
            if (status != 0)
            {
                perror("bind");

                printf("udp_init: Bind failed on port %d\n", sock->port);
                return CRYPTO_LIB_ERROR;
            }
            // }
        }
    }

    // Keep-alive socket option (not harmful for UDP, useful for TCP)
    optval = 1;
    optlen = sizeof(optval);
    setsockopt(sock->sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);

    return status;
}

static int32_t crypto_standalone_configure_tc(void)
{
    int32_t                      status = CRYPTO_LIB_SUCCESS;
    TCGvcidManagedParameters_t   managed_parameters = {0, CRYPTO_STANDALONE_TC_SCID, 0,
                                                       CRYPTO_STANDALONE_TC_HAS_FECF,
                                                       CRYPTO_STANDALONE_TC_HAS_SEGMENT_HDRS,
                                                       TC_MAX_FRAME_SIZE, 1};
    SecurityAssociation_t       *sa_ptr = NULL;

    memset(tc_gvcid_managed_parameters_array, 0, sizeof(tc_gvcid_managed_parameters_array));
    tc_gvcid_counter = 0;

    managed_parameters.vcid = 2;
    status                  = Crypto_Config_Add_TC_Gvcid_Managed_Parameters(managed_parameters);


    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }



    managed_parameters.vcid = 3;
    status                  = Crypto_Config_Add_TC_Gvcid_Managed_Parameters(managed_parameters);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    if (sa_if == NULL)
    {
        return CRYPTO_LIB_ERROR;
    }

    if (sa_if->sa_get_from_spi(2, &sa_ptr) == CRYPTO_LIB_SUCCESS)
    {
        sa_ptr->sa_state = SA_NONE;
    }
    if (sa_if->sa_get_from_spi(3, &sa_ptr) == CRYPTO_LIB_SUCCESS)
    {
        sa_ptr->sa_state        = SA_OPERATIONAL;
        sa_ptr->gvcid_blk.scid  = CRYPTO_STANDALONE_TC_SCID;
        sa_ptr->gvcid_blk.vcid  = 3;
        sa_ptr->gvcid_blk.mapid = TYPE_TC;
    }
    if (sa_if->sa_get_from_spi(4, &sa_ptr) == CRYPTO_LIB_SUCCESS)
    {
        sa_ptr->sa_state        = SA_OPERATIONAL;
        sa_ptr->gvcid_blk.scid  = CRYPTO_STANDALONE_TC_SCID;
        sa_ptr->gvcid_blk.vcid  = 2;
        sa_ptr->gvcid_blk.mapid = TYPE_TC;
    }

    return status;
}

int32_t crypto_reset(void)
{
    int32_t status;

    status = Crypto_Shutdown();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
    }

    status = Crypto_SC_Init();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
    }
    else
    {
        status = crypto_standalone_configure_tc();
        if (status != CRYPTO_LIB_SUCCESS)
        {
            printf("CryptoLib TC standalone configuration failed with error %d \n", status);
        }
    }

    return status;
}

void crypto_standalone_tc_frame(uint8_t *in_data, uint16_t in_length, uint8_t *out_data, uint16_t *out_length)
{
    /* TC Length */
    if (DYNAMIC_LENGTHS)
    {
        uint8_t segment_hdr_len = 1;
        uint8_t fecf_len        = tc_current_managed_parameters_struct.has_fecf ? 2 : 0;

        *out_length = TC_FRAME_HEADER_SIZE + segment_hdr_len + in_length + fecf_len;
    }
    else
    {
        *out_length = CRYPTO_STANDALONE_FRAMING_TC_DATA_LEN + 6;
    }

    /* TC Header */
    out_data[0] = 0x20;
    out_data[1] = CRYPTO_STANDALONE_FRAMING_SCID;
    out_data[2] = ((tc_vcid << 2) & 0xFC) | (((*out_length - 1) >> 8) & 0x03);
    out_data[3] = (*out_length - 1) & 0xFF;
    out_data[4] = tc_seq_num++;

    /* Segement Header */
    out_data[5] = 0xC0;

    /* SDLS Header */

    /* TC Data */
    memcpy(&out_data[6], in_data, in_length);

    /* SDLS Trailer */
}

void *crypto_standalone_tc_apply(void *socks)
{
    int32_t          status        = CRYPTO_LIB_SUCCESS;
    udp_interface_t *tc_socks      = (udp_interface_t *)socks;
    udp_info_t      *tc_read_sock  = &tc_socks->read;
    udp_info_t      *tc_write_sock = &tc_socks->write;

    uint8_t  tc_apply_in[TC_MAX_FRAME_SIZE];
    uint16_t tc_in_len = 0;
    uint8_t *tc_out_ptr = NULL;
    uint16_t tc_out_len = 0;

#ifdef CRYPTO_STANDALONE_HANDLE_FRAMING
    uint8_t tc_framed[TC_MAX_FRAME_SIZE] = {0};
#endif

    int sockaddr_size = sizeof(struct sockaddr_in);

    /* Prepare */
    memset(tc_apply_in, 0x00, sizeof(tc_apply_in));

    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        // /* Receive */
        status = recvfrom(tc_read_sock->sockfd, tc_apply_in, sizeof(tc_apply_in), 0,
                          (struct sockaddr *)&tc_read_sock->ip_address, (socklen_t *)&sockaddr_size);
        if (status != -1)
        {
            tc_in_len = status;
            if (tc_debug == 1)
            {
                printf("crypto_standalone_tc_apply - received[%d]: 0x", tc_in_len);
                for (int i = 0; i < status; i++)
                {
                    printf("%02x", tc_apply_in[i]);
                }
                printf("\n");
            }

/* Frame */
#ifdef CRYPTO_STANDALONE_WRAP_SPACE_PACKETS
            crypto_standalone_tc_frame(tc_apply_in, tc_in_len, tc_framed, &tc_out_len);
            memcpy(tc_apply_in, tc_framed, tc_out_len);
            tc_in_len  = tc_out_len;
            tc_out_len = 0;
            if (tc_debug == 1)
            {
                printf("crypto_standalone_tc_apply - framed[%d]: 0x", tc_in_len);
                for (int i = 0; i < tc_in_len; i++)
                {
                    printf("%02x", tc_apply_in[i]);
                }
                printf("\n");
            }
#endif

            /* Process */
            uint8_t tc_frame_vcid = 0;
            status                = crypto_standalone_get_tc_vcid(tc_apply_in, tc_in_len, &tc_frame_vcid);

            if (status != CRYPTO_LIB_SUCCESS)
            {
                int32_t reply_status;
                printf("crypto_standalone_tc_apply - dropping short TC frame\n");
                reply_status = crypto_standalone_send_envelope(tc_write_sock->sockfd, &tc_write_sock->saddr, tc_apply_in,
                                                               tc_in_len, NULL, 0, status, crypto_use_tcp);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_apply - Reply error %d \n", reply_status);
                }
                continue;
            }

            if (crypto_standalone_vcid_requires_security(tc_frame_vcid) == 0)
            {
                int32_t reply_status;
                reply_status = crypto_standalone_send_envelope(tc_write_sock->sockfd, &tc_write_sock->saddr, tc_apply_in,
                                                               tc_in_len, tc_apply_in, tc_in_len, CRYPTO_LIB_SUCCESS,
                                                               crypto_use_tcp);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_apply - Reply error %d \n", reply_status);
                }
                continue;
            }

            status = Crypto_TC_ApplySecurity(tc_apply_in, tc_in_len, &tc_out_ptr, &tc_out_len);
            crypto_config_tc.ignore_anti_replay = TC_IGNORE_ANTI_REPLAY_TRUE;
            if (status == CRYPTO_LIB_SUCCESS)
            {
                if (tc_debug == 1)
                {
                    printf("crypto_standalone_tc_apply - status = %d, encrypted[%d]: 0x", status, tc_out_len);
                    for (int i = 0; i < tc_out_len; i++)
                    {
                        printf("%02x", tc_out_ptr[i]);
                    }
                    printf("\n");
                }
                // printf("About to write to port %d!\n", tc_write_sock->port);
                /* Reply */
                int32_t reply_status;
                reply_status = crypto_standalone_send_envelope(tc_write_sock->sockfd, &tc_write_sock->saddr, tc_apply_in,
                                                               tc_in_len, tc_out_ptr, tc_out_len, CRYPTO_LIB_SUCCESS,
                                                               crypto_use_tcp);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_apply - Reply error %d \n", reply_status);
                }
                // printf("Allegedly wrote %d bytes to port %d!\n", tc_out_len, tc_write_sock->port);
            }
            else
            {
                int32_t reply_status;
                printf("crypto_standalone_tc_apply - ApplySecurity error %d \n", status);
                reply_status = crypto_standalone_send_envelope(tc_write_sock->sockfd, &tc_write_sock->saddr, tc_apply_in,
                                                               tc_in_len, NULL, 0, status, crypto_use_tcp);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_apply - Reply error %d \n", reply_status);
                }
            }

            /* Reset */
            memset(tc_apply_in, 0x00, sizeof(tc_apply_in));
            memset(tc_framed, 0x00, sizeof(tc_framed));
            tc_in_len  = 0;
            tc_out_len = 0;
            if (tc_out_ptr)
            {
                free(tc_out_ptr);
                tc_out_ptr = NULL;
            }
            if (tc_debug == 1)
            {
#ifdef CRYPTO_STANDALONE_TC_APPLY_DEBUG
                printf("\n");
#endif
            }
        }

        /* Delay */
        usleep(100);
    }
    close(tc_read_sock->sockfd);
    close(tc_write_sock->sockfd);
    return tc_read_sock;
}

void crypto_standalone_cleanup(const int signal)
{
    if (signal == SIGINT)
    {
        printf("\n");
        printf("Received CTRL+C, cleaning up... \n");
    }
    /* Signal threads to stop */
    keepRunning = CRYPTO_LIB_ERROR;
    exit(signal);
    return;
}

int main(int argc, char *argv[])
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    udp_interface_t tc_apply;

    pthread_t tc_apply_thread;

    tc_apply.read.sockfd        = -1;
    tc_apply.read.ip_address    = CRYPTOLIB_HOSTNAME;
    tc_apply.read.port          = TC_APPLY_PORT;
    tc_apply.write.sockfd       = -1;
    tc_apply.write.ip_address   = SC_HOSTNAME;
    tc_apply.write.port         = TC_APPLY_FWD_PORT;

    printf("Starting CryptoLib in LEMS-A3 TC apply security mode! \n");
    if (argc != 1)
    {
        printf("Invalid number of arguments! \n");
        printf("  Expected zero but received: %s \n", argv[1]);
    }
    printf("CryptoLib using %s sockets\n", crypto_use_tcp ? "TCP" : "UDP");

    /* Catch CTRL+C */
    signal(SIGINT, crypto_standalone_cleanup);

    status = crypto_standalone_apply_use_state_dir();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        keepRunning = CRYPTO_LIB_ERROR;
    }

    /* Initialize CryptoLib */
    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = crypto_reset();
        if (status != CRYPTO_LIB_SUCCESS)
        {
            printf("CryptoLib initialization failed with error %d \n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
    }

    /* Initialize sockets */
    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = crypto_standalone_socket_init(&tc_apply.read, TC_APPLY_PORT, 0, 0); // udp 6010
        if (status != CRYPTO_LIB_SUCCESS)
        {
            printf("crypto_standalone_socket_init tc_apply.read failed with status %d \n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
        else
        {
            status = crypto_standalone_socket_init(&tc_apply.write, TC_APPLY_FWD_PORT, 0,
                                                   crypto_use_tcp); // tcp, connect() 8010
            if (status != CRYPTO_LIB_SUCCESS)
            {
                printf("crypto_standalone_socket_init tc_apply.write failed with status %d \n", status);
                keepRunning = CRYPTO_LIB_ERROR;
            }
        }
    }

    /* Start threads */
    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        printf("  TC Apply \n");
        printf("    Read, UDP - %s : %d \n", tc_apply.read.ip_address, tc_apply.read.port);
        printf("    Write, %s - %s : %d \n", crypto_use_tcp ? "TCP" : "UDP", tc_apply.write.ip_address,
               tc_apply.write.port);
        printf("\n");

        status = pthread_create(&tc_apply_thread, NULL, *crypto_standalone_tc_apply, &tc_apply);
        if (status != 0)
        {
            printf("Failed to create tc_apply_thread thread: %d\n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
    }

    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = pthread_join(tc_apply_thread, NULL);
        if (status != 0)
        {
            printf("Failed to join tc_apply_thread thread: %d\n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
    }

    /* Cleanup */
    if (tc_apply.read.sockfd >= 0)
    {
        close(tc_apply.read.sockfd);
    }
    if (tc_apply.write.sockfd >= 0)
    {
        close(tc_apply.write.sockfd);
    }

    Crypto_Shutdown();

    printf("\n");
    exit(status);
}

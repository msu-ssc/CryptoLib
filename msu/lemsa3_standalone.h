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

#ifndef LEMSA3_STANDALONE_H
#define LEMSA3_STANDALONE_H

#ifdef __cplusplus
extern "C"
{
#endif

/*
** Includes
*/
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h> //hostent
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto.h"
#include "crypto_config.h"

/*
** Configuration
*/
#define CRYPTOLIB_HOSTNAME "cryptolib"
#define GSW_HOSTNAME       "cosmos"
#define SC_HOSTNAME        "radio-sim"

#ifndef CRYPTO_RX_GROUND_PORT
#define TC_APPLY_PORT 6010
#endif
#ifndef CRYPTO_RX_GROUND_PORT
#define TC_APPLY_FWD_PORT 8010
#endif

#define CRYPTO_STANDALONE_HANDLE_FRAMING
#define CRYPTO_STANDALONE_FRAMING_SCID        3
#define CRYPTO_STANDALONE_FRAMING_VCID        0x00
#define CRYPTO_STANDALONE_FRAMING_TC_DATA_LEN 512

/*
** Can be used to reduce ground system error messages
*/
#define CRYPTO_STANDALONE_DISCARD_IDLE_PACKETS
#define CRYPTO_STANDALONE_DISCARD_IDLE_FRAMES

/*
** Defines
*/
#define CRYPTO_STANDALONE_ENVELOPE_MAGIC      0x4D535543u /* "MSUC" */
#define CRYPTO_STANDALONE_ENVELOPE_VERSION    1
#define CRYPTO_STANDALONE_ENVELOPE_STATUS_LEN 8
#define CRYPTO_STANDALONE_ENVELOPE_KIND_SECURITY_RESPONSE 1
#define CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN 28
#define CRYPTO_STANDALONE_ENVELOPE_MAX_LEN    (CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN + (TC_MAX_FRAME_SIZE * 2))

    /*
    ** Structures
    */
    typedef struct
    {
        int                sockfd;
        char              *ip_address;
        int                port;
        struct sockaddr_in saddr;
    } udp_info_t;

    typedef struct
    {
        udp_info_t read;
        udp_info_t write;
    } udp_interface_t;

    static inline void crypto_standalone_write_u16(uint8_t *buf, uint16_t value)
    {
        buf[0] = (uint8_t)((value >> 8) & 0xFF);
        buf[1] = (uint8_t)(value & 0xFF);
    }

    static inline void crypto_standalone_write_u32(uint8_t *buf, uint32_t value)
    {
        buf[0] = (uint8_t)((value >> 24) & 0xFF);
        buf[1] = (uint8_t)((value >> 16) & 0xFF);
        buf[2] = (uint8_t)((value >> 8) & 0xFF);
        buf[3] = (uint8_t)(value & 0xFF);
    }

    static inline int32_t crypto_standalone_send_envelope(int sockfd, const struct sockaddr_in *addr,
                                                          const uint8_t *input, uint16_t input_len,
                                                          const uint8_t *output, uint16_t output_len,
                                                          int32_t crypto_status, uint8_t use_tcp)
    {
        uint8_t     envelope[CRYPTO_STANDALONE_ENVELOPE_MAX_LEN];
        const char *status_text = crypto_status == CRYPTO_LIB_SUCCESS ? "SUCCESS" : "FAIL";
        uint32_t    payload_len = (uint32_t)input_len + (uint32_t)output_len;
        uint32_t    envelope_len;
        ssize_t     sent;

        if ((input_len > 0 && input == NULL) || (output_len > 0 && output == NULL))
        {
            return CRYPTO_LIB_ERROR;
        }
        if (use_tcp == 0 && addr == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }
        if (payload_len > (CRYPTO_STANDALONE_ENVELOPE_MAX_LEN - CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN))
        {
            return CRYPTO_LIB_ERROR;
        }

        memset(envelope, 0, sizeof(envelope));
        crypto_standalone_write_u32(&envelope[0], CRYPTO_STANDALONE_ENVELOPE_MAGIC);
        envelope[4] = CRYPTO_STANDALONE_ENVELOPE_VERSION;
        envelope[5] = CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN;
        crypto_standalone_write_u16(&envelope[6], CRYPTO_STANDALONE_ENVELOPE_KIND_SECURITY_RESPONSE);
        crypto_standalone_write_u32(&envelope[8], payload_len);
        memcpy(&envelope[12], status_text, strlen(status_text));
        crypto_standalone_write_u32(&envelope[20], (uint32_t)crypto_status);
        crypto_standalone_write_u16(&envelope[24], input_len);
        crypto_standalone_write_u16(&envelope[26], output_len);

        if (input_len > 0)
        {
            memcpy(&envelope[CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN], input, input_len);
        }
        if (output_len > 0)
        {
            memcpy(&envelope[CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN + input_len], output, output_len);
        }

        envelope_len = CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN + payload_len;
        if (use_tcp)
        {
            sent = send(sockfd, envelope, envelope_len, 0);
        }
        else
        {
            sent = sendto(sockfd, envelope, envelope_len, 0, (const struct sockaddr *)addr, sizeof(*addr));
        }

        if (sent == -1 || (uint32_t)sent != envelope_len)
        {
            return CRYPTO_LIB_ERROR;
        }
        return CRYPTO_LIB_SUCCESS;
    }

    /*
    ** Prototypes
    */
    int32_t crypto_host_to_ip(const char *hostname, char *ip);
    int32_t crypto_standalone_socket_init(udp_info_t *sock, int32_t port, uint8_t bind_sock, int connection);
    int32_t crypto_reset(void);
    void    crypto_standalone_tc_frame(uint8_t *in_data, uint16_t in_length, uint8_t *out_data, uint16_t *out_length);
    void   *crypto_standalone_tc_apply(void *socks);
    void    crypto_standalone_cleanup(const int signal);

#ifdef __cplusplus
} /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif // LEMSA3_STANDALONE_H

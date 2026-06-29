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
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "crypto_config.h"

/*
** Configuration
*/
#define CRYPTO_STANDALONE_LOOPBACK "127.0.0.1"
#define CRYPTOLIB_HOSTNAME         CRYPTO_STANDALONE_LOOPBACK
#define GSW_HOSTNAME               CRYPTO_STANDALONE_LOOPBACK
#define SC_HOSTNAME                CRYPTO_STANDALONE_LOOPBACK

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
#define CRYPTO_STANDALONE_ENVELOPE_KIND_STATUS_MESSAGE    2
#define CRYPTO_STANDALONE_ENVELOPE_KIND_ANTI_REPLAY_COUNTER_SET_REQUEST 3
#define CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN 28
#define CRYPTO_STANDALONE_ENVELOPE_MAX_LEN    (CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN + (TC_MAX_FRAME_SIZE * 2))
#define CRYPTO_STANDALONE_STATUS_TIMESTAMP_LEN 32
#define CRYPTO_STANDALONE_STATUS_MESSAGE_MAX_LEN 2048
#define CRYPTO_STANDALONE_STATUS_INTERVAL_SECONDS 10
#define CRYPTO_STANDALONE_STATUS_VCID_COUNT 3
#define CRYPTO_STANDALONE_COUNTER_DECIMAL_MAX_LEN 80
#define CRYPTO_STANDALONE_COUNTER_HEX_MAX_LEN     ((MAX_IV_LEN * 2) + 1)
#define CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MIN_LEN 2
#define CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MAX_COUNTER_LEN MAX_IV_LEN
#define CRYPTO_STANDALONE_COUNTER_SET_RESPONSE_MAX_LEN 512

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

    typedef struct
    {
        uint64_t attempts;
        uint64_t successes;
        char     recent_attempt[CRYPTO_STANDALONE_STATUS_TIMESTAMP_LEN];
        char     recent_result[CRYPTO_STANDALONE_ENVELOPE_STATUS_LEN + 1];
    } crypto_standalone_vcid_status_t;

    typedef struct
    {
        pthread_mutex_t                  lock;
        crypto_standalone_vcid_status_t vcid[64];
    } crypto_standalone_status_tracker_t;

    typedef struct
    {
        udp_info_t                         *write_sock;
        crypto_standalone_status_tracker_t *tracker;
        const char                         *attempt_label;
        volatile uint8_t                   *keep_running;
        uint8_t                             use_tcp;
    } crypto_standalone_status_reporter_args_t;

#define CRYPTO_STANDALONE_STATUS_TRACKER_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, {{0}}}

    static inline int32_t crypto_standalone_send_status_envelope(int sockfd, const struct sockaddr_in *addr,
                                                                 const char *message, uint8_t use_tcp);

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

    static inline uint16_t crypto_standalone_read_u16(const uint8_t *buf)
    {
        return (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
    }

    static inline uint32_t crypto_standalone_read_u32(const uint8_t *buf)
    {
        return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    }

    static inline int32_t crypto_standalone_set_ipv4_addr(udp_info_t *sock)
    {
        if (inet_pton(AF_INET, sock->ip_address, &sock->saddr.sin_addr) != 1)
        {
            printf("socket_init: Invalid IPv4 address '%s'\n", sock->ip_address);
            return CRYPTO_LIB_ERROR;
        }

        sock->saddr.sin_family = AF_INET;
        sock->saddr.sin_port   = htons(sock->port);
        return CRYPTO_LIB_SUCCESS;
    }

    static inline const char *crypto_standalone_status_text(int32_t status)
    {
        return status == CRYPTO_LIB_SUCCESS ? "SUCCESS" : "FAIL";
    }

    static inline void crypto_standalone_current_time(char *buf, size_t buf_len)
    {
        struct timeval now;
        struct tm      utc_time;
        char           prefix[24];

        if (buf_len == 0)
        {
            return;
        }

        if (gettimeofday(&now, NULL) != 0 || gmtime_r(&now.tv_sec, &utc_time) == NULL ||
            strftime(prefix, sizeof(prefix), "%Y-%m-%dT%H:%M:%S", &utc_time) == 0)
        {
            snprintf(buf, buf_len, "unknown");
            return;
        }

        snprintf(buf, buf_len, "%s.%03ld+00:00", prefix, (long)(now.tv_usec / 1000));
    }

    static inline void crypto_standalone_note_attempt(crypto_standalone_status_tracker_t *tracker, uint8_t vcid,
                                                      int32_t status)
    {
        crypto_standalone_vcid_status_t *vcid_status;

        if (tracker == NULL || vcid >= 64)
        {
            return;
        }

        pthread_mutex_lock(&tracker->lock);
        vcid_status = &tracker->vcid[vcid];
        vcid_status->attempts++;
        if (status == CRYPTO_LIB_SUCCESS)
        {
            vcid_status->successes++;
        }
        crypto_standalone_current_time(vcid_status->recent_attempt, sizeof(vcid_status->recent_attempt));
        snprintf(vcid_status->recent_result, sizeof(vcid_status->recent_result), "%s",
                 crypto_standalone_status_text(status));
        pthread_mutex_unlock(&tracker->lock);
    }

    static inline void crypto_standalone_counter_to_decimal(const uint8_t *counter, uint8_t counter_len, char *buf,
                                                            size_t buf_len)
    {
        uint8_t digits[CRYPTO_STANDALONE_COUNTER_DECIMAL_MAX_LEN];
        size_t  digit_count = 1;
        size_t  out_index   = 0;

        if (buf_len == 0)
        {
            return;
        }

        if (counter == NULL || counter_len == 0)
        {
            snprintf(buf, buf_len, "0");
            return;
        }

        memset(digits, 0, sizeof(digits));
        for (uint8_t i = 0; i < counter_len; i++)
        {
            uint16_t carry = counter[i];
            for (size_t digit_index = 0; digit_index < digit_count; digit_index++)
            {
                uint16_t value       = (uint16_t)(digits[digit_index] * 256) + carry;
                digits[digit_index]  = value % 10;
                carry                = value / 10;
            }
            while (carry > 0 && digit_count < sizeof(digits))
            {
                digits[digit_count] = carry % 10;
                carry /= 10;
                digit_count++;
            }
        }

        while (digit_count > 1 && digits[digit_count - 1] == 0)
        {
            digit_count--;
        }

        while (digit_count > 0 && out_index + 1 < buf_len)
        {
            digit_count--;
            buf[out_index] = (char)('0' + digits[digit_count]);
            out_index++;
        }
        buf[out_index] = '\0';
    }

    static inline void crypto_standalone_counter_to_hex(const uint8_t *counter, uint8_t counter_len, char *buf,
                                                        size_t buf_len)
    {
        size_t offset = 0;
        uint8_t first_nonzero = 0;

        if (buf_len == 0)
        {
            return;
        }

        if (counter == NULL || counter_len == 0)
        {
            snprintf(buf, buf_len, "0");
            return;
        }

        while (first_nonzero < counter_len && counter[first_nonzero] == 0)
        {
            first_nonzero++;
        }

        if (first_nonzero == counter_len)
        {
            snprintf(buf, buf_len, "0");
            return;
        }

        offset = (size_t)snprintf(buf, buf_len, "%X", counter[first_nonzero]);
        for (uint8_t i = first_nonzero + 1; i < counter_len && offset < buf_len; i++)
        {
            int written = snprintf(&buf[offset], buf_len - offset, "%02X", counter[i]);
            if (written < 0 || (size_t)written >= buf_len - offset)
            {
                buf[buf_len - 1] = '\0';
                return;
            }
            offset += (size_t)written;
        }
    }

    static inline void crypto_standalone_counter_to_fixed_hex(const uint8_t *counter, uint8_t counter_len, char *buf,
                                                              size_t buf_len)
    {
        size_t offset = 0;

        if (buf_len == 0)
        {
            return;
        }

        if (counter == NULL || counter_len == 0)
        {
            snprintf(buf, buf_len, "0");
            return;
        }

        for (uint8_t i = 0; i < counter_len && offset < buf_len; i++)
        {
            int written = snprintf(&buf[offset], buf_len - offset, "%02X", counter[i]);
            if (written < 0 || (size_t)written >= buf_len - offset)
            {
                buf[buf_len - 1] = '\0';
                return;
            }
            offset += (size_t)written;
        }
    }

    static inline int32_t crypto_standalone_get_actual_antireplay_counter_mutable(SecurityAssociation_t *sa_ptr,
                                                                                  uint8_t **counter,
                                                                                  uint8_t *counter_len)
    {
        if (counter == NULL || counter_len == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }

        *counter     = NULL;
        *counter_len = 0;
        if (sa_ptr == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }

        if ((sa_ptr->ecs == CRYPTO_CIPHER_AES256_GCM || sa_ptr->ecs == CRYPTO_CIPHER_AES256_GCM_SIV) &&
            sa_ptr->iv_len > 0)
        {
            *counter     = sa_ptr->iv;
            *counter_len = sa_ptr->iv_len;
            return CRYPTO_LIB_SUCCESS;
        }

        if (sa_ptr->shsnf_len > 0 && sa_ptr->arsn_len > 0)
        {
            *counter     = sa_ptr->arsn;
            *counter_len = sa_ptr->arsn_len;
            return CRYPTO_LIB_SUCCESS;
        }

        return CRYPTO_LIB_SUCCESS;
    }

    static inline int32_t crypto_standalone_get_actual_antireplay_counter(SecurityAssociation_t *sa_ptr,
                                                                          const uint8_t **counter,
                                                                          uint8_t *counter_len)
    {
        uint8_t *mutable_counter = NULL;
        int32_t  status;

        if (counter == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }

        status = crypto_standalone_get_actual_antireplay_counter_mutable(sa_ptr, &mutable_counter, counter_len);
        if (status == CRYPTO_LIB_SUCCESS)
        {
            *counter = mutable_counter;
        }

        return status;
    }

    static inline int32_t crypto_standalone_vcid_to_spi(uint8_t vcid, uint16_t *spi)
    {
        if (spi == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }

        if (vcid == 2)
        {
            *spi = 4;
            return CRYPTO_LIB_SUCCESS;
        }
        if (vcid == 3)
        {
            *spi = 3;
            return CRYPTO_LIB_SUCCESS;
        }

        return CRYPTO_LIB_ERROR;
    }

    static inline void crypto_standalone_get_antireplay_counter_text(uint8_t vcid, char *decimal, size_t decimal_len,
                                                                     char *hex, size_t hex_len)
    {
        SecurityAssociation_t *sa_ptr = NULL;
        const uint8_t         *counter = NULL;
        uint8_t                counter_len = 0;
        uint16_t               spi = 0;

        if (decimal_len > 0)
        {
            snprintf(decimal, decimal_len, "0");
        }
        if (hex_len > 0)
        {
            snprintf(hex, hex_len, "0");
        }

        if (sa_if == NULL || crypto_standalone_vcid_to_spi(vcid, &spi) != CRYPTO_LIB_SUCCESS)
        {
            return;
        }
        if (sa_if->sa_get_from_spi(spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
        {
            return;
        }
        if (crypto_standalone_get_actual_antireplay_counter(sa_ptr, &counter, &counter_len) != CRYPTO_LIB_SUCCESS)
        {
            return;
        }

        crypto_standalone_counter_to_decimal(counter, counter_len, decimal, decimal_len);
        crypto_standalone_counter_to_hex(counter, counter_len, hex, hex_len);
    }

    static inline int32_t crypto_standalone_set_antireplay_counter(uint8_t vcid, const uint8_t *new_counter,
                                                                   uint8_t new_counter_len, char *previous_hex,
                                                                   size_t previous_hex_len, char *new_hex,
                                                                   size_t new_hex_len)
    {
        SecurityAssociation_t *sa_ptr = NULL;
        uint8_t               *counter = NULL;
        uint8_t                counter_len = 0;
        uint16_t               spi = 0;
        int32_t                status;

        if (previous_hex_len > 0)
        {
            snprintf(previous_hex, previous_hex_len, "0");
        }
        if (new_hex_len > 0)
        {
            snprintf(new_hex, new_hex_len, "0");
        }

        if (new_counter == NULL || sa_if == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }
        status = crypto_standalone_vcid_to_spi(vcid, &spi);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            return status;
        }
        status = sa_if->sa_get_from_spi(spi, &sa_ptr);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            return status;
        }
        status = crypto_standalone_get_actual_antireplay_counter_mutable(sa_ptr, &counter, &counter_len);
        if (status != CRYPTO_LIB_SUCCESS || counter == NULL || counter_len == 0)
        {
            return CRYPTO_LIB_ERROR;
        }
        if (new_counter_len != counter_len)
        {
            return CRYPTO_LIB_ERROR;
        }

        crypto_standalone_counter_to_fixed_hex(counter, counter_len, previous_hex, previous_hex_len);
        crypto_standalone_counter_to_fixed_hex(new_counter, new_counter_len, new_hex, new_hex_len);
        memcpy(counter, new_counter, counter_len);

        return sa_if->sa_save_sa(sa_ptr);
    }

    static inline void crypto_standalone_format_counter_set_response(char *message, size_t message_len, uint8_t vcid,
                                                                     const char *previous_hex, const char *new_hex,
                                                                     int32_t status)
    {
        char now[CRYPTO_STANDALONE_STATUS_TIMESTAMP_LEN];

        if (message_len == 0)
        {
            return;
        }

        crypto_standalone_current_time(now, sizeof(now));
        if (status == CRYPTO_LIB_SUCCESS)
        {
            snprintf(message, message_len,
                     "{\"current_time\":\"%s\",\"anti_replay_counter_modification\":{\"vcid\":%u,"
                     "\"previous_counter_hex\":\"%s\",\"new_counter_hex\":\"%s\"}}",
                     now, vcid, previous_hex == NULL ? "0" : previous_hex, new_hex == NULL ? "0" : new_hex);
        }
        else
        {
            snprintf(message, message_len,
                     "{\"current_time\":\"%s\",\"anti_replay_counter_modification\":{\"vcid\":%u,"
                     "\"previous_counter_hex\":\"%s\",\"new_counter_hex\":\"%s\",\"error\":%d}}",
                     now, vcid, previous_hex == NULL ? "0" : previous_hex, new_hex == NULL ? "0" : new_hex, status);
        }
    }

    static inline int32_t crypto_standalone_parse_counter_set_request(const uint8_t *data, uint16_t data_len,
                                                                      uint8_t *vcid, const uint8_t **new_counter,
                                                                      uint8_t *new_counter_len)
    {
        uint32_t payload_len;
        uint16_t kind;

        if (data == NULL || vcid == NULL || new_counter == NULL || new_counter_len == NULL ||
            data_len < CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN)
        {
            return CRYPTO_LIB_ERROR;
        }
        if (crypto_standalone_read_u32(&data[0]) != CRYPTO_STANDALONE_ENVELOPE_MAGIC ||
            data[4] != CRYPTO_STANDALONE_ENVELOPE_VERSION || data[5] != CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN)
        {
            return CRYPTO_LIB_ERROR;
        }

        kind = crypto_standalone_read_u16(&data[6]);
        if (kind != CRYPTO_STANDALONE_ENVELOPE_KIND_ANTI_REPLAY_COUNTER_SET_REQUEST)
        {
            return CRYPTO_LIB_ERROR;
        }

        payload_len = crypto_standalone_read_u32(&data[8]);
        if (payload_len < CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MIN_LEN ||
            payload_len > (CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MIN_LEN +
                           CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MAX_COUNTER_LEN) ||
            payload_len != (uint32_t)(data_len - CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN))
        {
            return CRYPTO_LIB_ERROR;
        }

        *vcid            = data[CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN];
        *new_counter_len = data[CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN + 1];
        if (*new_counter_len == 0 ||
            payload_len != (uint32_t)(CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MIN_LEN + *new_counter_len))
        {
            return CRYPTO_LIB_ERROR;
        }
        *new_counter = &data[CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN + CRYPTO_STANDALONE_COUNTER_SET_REQUEST_MIN_LEN];
        return CRYPTO_LIB_SUCCESS;
    }

    static inline uint8_t crypto_standalone_is_counter_set_request(const uint8_t *data, uint16_t data_len)
    {
        return data != NULL && data_len >= CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN &&
               crypto_standalone_read_u32(&data[0]) == CRYPTO_STANDALONE_ENVELOPE_MAGIC &&
               data[4] == CRYPTO_STANDALONE_ENVELOPE_VERSION &&
               data[5] == CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN &&
               crypto_standalone_read_u16(&data[6]) ==
                   CRYPTO_STANDALONE_ENVELOPE_KIND_ANTI_REPLAY_COUNTER_SET_REQUEST;
    }

    static inline int32_t crypto_standalone_handle_counter_set_request(int sockfd, const struct sockaddr_in *addr,
                                                                       const uint8_t *data, uint16_t data_len,
                                                                       uint8_t use_tcp, uint8_t *handled)
    {
        char           previous_hex[CRYPTO_STANDALONE_COUNTER_HEX_MAX_LEN];
        char           new_hex[CRYPTO_STANDALONE_COUNTER_HEX_MAX_LEN];
        char           response[CRYPTO_STANDALONE_COUNTER_SET_RESPONSE_MAX_LEN];
        const uint8_t *new_counter = NULL;
        uint8_t        new_counter_len = 0;
        uint8_t        vcid = 0;
        int32_t        status;

        if (handled == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }
        *handled = CRYPTO_FALSE;

        if (crypto_standalone_is_counter_set_request(data, data_len) == 0)
        {
            return CRYPTO_LIB_SUCCESS;
        }
        *handled = CRYPTO_TRUE;

        snprintf(previous_hex, sizeof(previous_hex), "0");
        snprintf(new_hex, sizeof(new_hex), "0");
        status = crypto_standalone_parse_counter_set_request(data, data_len, &vcid, &new_counter, &new_counter_len);
        if (status == CRYPTO_LIB_SUCCESS)
        {
            status = crypto_standalone_set_antireplay_counter(vcid, new_counter, new_counter_len, previous_hex,
                                                              sizeof(previous_hex), new_hex, sizeof(new_hex));
        }

        crypto_standalone_format_counter_set_response(response, sizeof(response), vcid, previous_hex, new_hex, status);
        return crypto_standalone_send_status_envelope(sockfd, addr, response, use_tcp);
    }

    static inline int32_t crypto_standalone_send_envelope(int sockfd, const struct sockaddr_in *addr,
                                                          const uint8_t *input, uint16_t input_len,
                                                          const uint8_t *output, uint16_t output_len,
                                                          int32_t crypto_status, uint8_t use_tcp)
    {
        uint8_t     envelope[CRYPTO_STANDALONE_ENVELOPE_MAX_LEN];
        const char *status_text = crypto_standalone_status_text(crypto_status);
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

    static inline int32_t crypto_standalone_send_status_envelope(int sockfd, const struct sockaddr_in *addr,
                                                                 const char *message, uint8_t use_tcp)
    {
        uint8_t  envelope[CRYPTO_STANDALONE_ENVELOPE_MAX_LEN];
        uint32_t payload_len;
        uint32_t envelope_len;
        ssize_t  sent;

        if (message == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }
        if (use_tcp == 0 && addr == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }

        payload_len = (uint32_t)strlen(message);
        if (payload_len > (CRYPTO_STANDALONE_ENVELOPE_MAX_LEN - CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN))
        {
            return CRYPTO_LIB_ERROR;
        }

        memset(envelope, 0, sizeof(envelope));
        crypto_standalone_write_u32(&envelope[0], CRYPTO_STANDALONE_ENVELOPE_MAGIC);
        envelope[4] = CRYPTO_STANDALONE_ENVELOPE_VERSION;
        envelope[5] = CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN;
        crypto_standalone_write_u16(&envelope[6], CRYPTO_STANDALONE_ENVELOPE_KIND_STATUS_MESSAGE);
        crypto_standalone_write_u32(&envelope[8], payload_len);
        if (payload_len > 0)
        {
            memcpy(&envelope[CRYPTO_STANDALONE_ENVELOPE_HEADER_LEN], message, payload_len);
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

    static inline void crypto_standalone_format_status_message(crypto_standalone_status_tracker_t *tracker,
                                                               const char *attempt_label, char *message,
                                                               size_t message_len)
    {
        static const uint8_t             status_vcids[CRYPTO_STANDALONE_STATUS_VCID_COUNT] = {0, 2, 3};
        char                             now[CRYPTO_STANDALONE_STATUS_TIMESTAMP_LEN];
        crypto_standalone_vcid_status_t vcid_status[CRYPTO_STANDALONE_STATUS_VCID_COUNT];
        int                              offset;

        if (message_len == 0)
        {
            return;
        }

        (void)attempt_label;
        memset(vcid_status, 0, sizeof(vcid_status));
        crypto_standalone_current_time(now, sizeof(now));

        if (tracker != NULL)
        {
            pthread_mutex_lock(&tracker->lock);
            for (size_t i = 0; i < CRYPTO_STANDALONE_STATUS_VCID_COUNT; i++)
            {
                vcid_status[i] = tracker->vcid[status_vcids[i]];
            }
            pthread_mutex_unlock(&tracker->lock);
        }

        offset = snprintf(message, message_len, "{\"current_time\":\"%s\",\"vcids\":{", now);
        if (offset < 0 || (size_t)offset >= message_len)
        {
            message[message_len - 1] = '\0';
            return;
        }

        for (size_t i = 0; i < CRYPTO_STANDALONE_STATUS_VCID_COUNT; i++)
        {
            char        counter_decimal[CRYPTO_STANDALONE_COUNTER_DECIMAL_MAX_LEN];
            char        counter_hex[CRYPTO_STANDALONE_COUNTER_HEX_MAX_LEN];
            const char *recent_attempt = vcid_status[i].attempts == 0 ? "never" : vcid_status[i].recent_attempt;
            const char *recent_result  = vcid_status[i].attempts == 0 ? "NONE" : vcid_status[i].recent_result;
            const char *separator      = i == 0 ? "" : ",";
            int         written;

            crypto_standalone_get_antireplay_counter_text(status_vcids[i], counter_decimal, sizeof(counter_decimal),
                                                          counter_hex, sizeof(counter_hex));

            written = snprintf(&message[offset], message_len - (size_t)offset,
                               "%s\"%u\":{\"attempts\":%llu,\"successes\":%llu,\"most_recent_timestamp\":\"%s\","
                               "\"most_recent_result\":\"%s\",\"arsn\":%s,\"arsn_hex\":\"%s\"}",
                               separator, status_vcids[i], (unsigned long long)vcid_status[i].attempts,
                               (unsigned long long)vcid_status[i].successes, recent_attempt, recent_result,
                               counter_decimal, counter_hex);
            if (written < 0 || (size_t)written >= message_len - (size_t)offset)
            {
                message[message_len - 1] = '\0';
                return;
            }
            offset += written;
        }

        if ((size_t)offset + 3 > message_len)
        {
            message[message_len - 1] = '\0';
            return;
        }
        snprintf(&message[offset], message_len - (size_t)offset, "}}");
    }

    static inline int32_t crypto_standalone_emit_status(crypto_standalone_status_reporter_args_t *args)
    {
        char message[CRYPTO_STANDALONE_STATUS_MESSAGE_MAX_LEN];

        if (args == NULL || args->write_sock == NULL)
        {
            return CRYPTO_LIB_ERROR;
        }

        crypto_standalone_format_status_message(args->tracker, args->attempt_label, message, sizeof(message));
        printf("%s\n", message);
        fflush(stdout);
        return crypto_standalone_send_status_envelope(args->write_sock->sockfd, &args->write_sock->saddr, message,
                                                      args->use_tcp);
    }

    static inline void *crypto_standalone_status_reporter(void *arg)
    {
        crypto_standalone_status_reporter_args_t *args = (crypto_standalone_status_reporter_args_t *)arg;

        while (args != NULL && args->keep_running != NULL && *args->keep_running == CRYPTO_LIB_SUCCESS)
        {
            sleep(CRYPTO_STANDALONE_STATUS_INTERVAL_SECONDS);
            if (*args->keep_running == CRYPTO_LIB_SUCCESS &&
                crypto_standalone_emit_status(args) != CRYPTO_LIB_SUCCESS)
            {
                printf("crypto_standalone_status_reporter - status envelope send failed\n");
            }
        }

        return NULL;
    }

    /*
    ** Prototypes
    */
    int32_t crypto_standalone_socket_init(udp_info_t *sock, int32_t port, uint8_t bind_sock, int connection);
    int32_t crypto_reset(void);
    void    crypto_standalone_tc_frame(uint8_t *in_data, uint16_t in_length, uint8_t *out_data, uint16_t *out_length);
    void   *crypto_standalone_tc_apply(void *socks);
    void    crypto_standalone_cleanup(const int signal);

#ifdef __cplusplus
} /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif // LEMSA3_STANDALONE_H

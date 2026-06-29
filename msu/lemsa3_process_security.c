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
** Standalone CryptoLib TC Process Implementation
** UDP interface to remove TC frame security and return the unsecured TC frame.
*******************************************************************************/

#include "lemsa3_standalone.h"

#include <errno.h>
#include <sys/stat.h>

#ifndef TC_PROCESS_PORT
#define TC_PROCESS_PORT 6012
#endif
#ifndef TC_PROCESS_FWD_PORT
#define TC_PROCESS_FWD_PORT 8012
#endif

#define CRYPTO_STANDALONE_PROCESS_SCID             119
#define CRYPTO_STANDALONE_PROCESS_TC_HAS_FECF      TC_HAS_FECF
#define CRYPTO_STANDALONE_PROCESS_TC_HAS_SEG_HDRS  TC_NO_SEGMENT_HDRS
#define CRYPTO_STANDALONE_PROCESS_STATE_DIR        "standalone_process_state"
#define CRYPTO_STANDALONE_PROCESS_ANTI_REPLAY_IGNORE_ARG  "--anti-replay=ignore"
#define CRYPTO_STANDALONE_PROCESS_ANTI_REPLAY_ENFORCE_ARG "--anti-replay=enforce"

static volatile uint8_t keepRunning = CRYPTO_LIB_SUCCESS;
static volatile uint8_t tc_debug    = 1;
static uint8_t          tc_ignore_anti_replay = TC_IGNORE_ANTI_REPLAY_FALSE;
static crypto_standalone_status_tracker_t tc_status = CRYPTO_STANDALONE_STATUS_TRACKER_INITIALIZER;

static const char *crypto_standalone_process_anti_replay_mode(void)
{
    return tc_ignore_anti_replay == TC_IGNORE_ANTI_REPLAY_TRUE ? "ignore" : "enforce";
}

static uint8_t crypto_standalone_process_anti_replay_enforced(void)
{
    return crypto_config_tc.ignore_anti_replay == TC_IGNORE_ANTI_REPLAY_FALSE ? CRYPTO_TRUE : CRYPTO_FALSE;
}

static void crypto_standalone_process_print_usage(const char *program_name)
{
    printf("Usage: %s [--anti-replay=ignore|enforce]\n", program_name);
    printf("  Default: --anti-replay=enforce\n");
}

static int32_t crypto_standalone_process_parse_args(int argc, char *argv[])
{
    if (argc == 1)
    {
        return CRYPTO_LIB_SUCCESS;
    }

    if (argc == 2 && strcmp(argv[1], CRYPTO_STANDALONE_PROCESS_ANTI_REPLAY_IGNORE_ARG) == 0)
    {
        tc_ignore_anti_replay = TC_IGNORE_ANTI_REPLAY_TRUE;
        return CRYPTO_LIB_SUCCESS;
    }

    if (argc == 2 && strcmp(argv[1], CRYPTO_STANDALONE_PROCESS_ANTI_REPLAY_ENFORCE_ARG) == 0)
    {
        tc_ignore_anti_replay = TC_IGNORE_ANTI_REPLAY_FALSE;
        return CRYPTO_LIB_SUCCESS;
    }

    crypto_standalone_process_print_usage(argv[0]);
    return CRYPTO_LIB_ERROR;
}

static int32_t crypto_standalone_process_use_state_dir(void)
{
    if (mkdir(CRYPTO_STANDALONE_PROCESS_STATE_DIR, 0775) != 0 && errno != EEXIST)
    {
        perror("mkdir");
        return CRYPTO_LIB_ERROR;
    }

    if (chdir(CRYPTO_STANDALONE_PROCESS_STATE_DIR) != 0)
    {
        perror("chdir");
        return CRYPTO_LIB_ERROR;
    }

    return CRYPTO_LIB_SUCCESS;
}

static uint8_t crypto_standalone_process_vcid_requires_security(uint8_t vcid)
{
    return (vcid == 2 || vcid == 3);
}

static int32_t crypto_standalone_process_set_anti_replay_enforcement(uint8_t enforce, uint8_t *before,
                                                                      uint8_t *after)
{
    uint8_t new_ignore_anti_replay;
    int32_t status;

    if (before != NULL)
    {
        *before = crypto_standalone_process_anti_replay_enforced();
    }

    new_ignore_anti_replay = enforce == CRYPTO_TRUE ? TC_IGNORE_ANTI_REPLAY_FALSE : TC_IGNORE_ANTI_REPLAY_TRUE;
    status                 = Crypto_Config_TC(crypto_config_tc.crypto_create_fecf, crypto_config_tc.process_sdls_pdus,
                                              crypto_config_tc.has_pus_hdr, new_ignore_anti_replay,
                                              crypto_config_tc.ignore_sa_state, crypto_config_tc.unique_sa_per_mapid,
                                              crypto_config_tc.crypto_check_fecf, crypto_config_tc.vcid_bitmask,
                                              crypto_config_tc.crypto_increment_nontransmitted_iv);
    if (status == CRYPTO_LIB_SUCCESS)
    {
        tc_ignore_anti_replay = new_ignore_anti_replay;
    }

    if (after != NULL)
    {
        *after = crypto_standalone_process_anti_replay_enforced();
    }

    return status;
}

static int32_t crypto_standalone_process_handle_anti_replay_enforcement_request(int sockfd,
                                                                                const struct sockaddr_in *addr,
                                                                                const uint8_t *data,
                                                                                uint16_t data_len, uint8_t *handled)
{
    char    response[CRYPTO_STANDALONE_ANTI_REPLAY_ENFORCEMENT_SET_RESPONSE_MAX_LEN];
    uint8_t after = crypto_standalone_process_anti_replay_enforced();
    uint8_t before = after;
    uint8_t enforce = CRYPTO_FALSE;
    int32_t status;

    if (handled == NULL)
    {
        return CRYPTO_LIB_ERROR;
    }
    *handled = CRYPTO_FALSE;

    if (crypto_standalone_is_anti_replay_enforcement_set_request(data, data_len) == 0)
    {
        return CRYPTO_LIB_SUCCESS;
    }
    *handled = CRYPTO_TRUE;

    status = crypto_standalone_parse_anti_replay_enforcement_set_request(data, data_len, &enforce);
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = crypto_standalone_process_set_anti_replay_enforcement(enforce, &before, &after);
    }

    crypto_standalone_format_anti_replay_enforcement_response(response, sizeof(response), before, after, status);
    return crypto_standalone_send_status_envelope(sockfd, addr, response, 0);
}

static int32_t crypto_standalone_process_get_tc_vcid(const uint8_t *frame, uint16_t frame_len, uint8_t *vcid)
{
    if (frame_len < TC_FRAME_HEADER_SIZE)
    {
        return CRYPTO_LIB_ERROR;
    }

    *vcid = (frame[2] >> 2) & 0x3F;
    return CRYPTO_LIB_SUCCESS;
}

static int32_t crypto_standalone_process_socket_init(udp_info_t *sock, int32_t port, uint8_t bind_sock)
{
    int status = CRYPTO_LIB_SUCCESS;

    sock->port   = port;
    sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock->sockfd == -1)
    {
        printf("udp_init: Socket create error port %d \n", sock->port);
        return CRYPTO_LIB_ERROR;
    }

    status = crypto_standalone_set_ipv4_addr(sock);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    if (bind_sock)
    {
        status = bind(sock->sockfd, (struct sockaddr *)&sock->saddr, sizeof(sock->saddr));
        if (status != 0)
        {
            perror("bind");
            printf("udp_init: Bind failed on port %d\n", sock->port);
            return CRYPTO_LIB_ERROR;
        }
    }

    return status;
}

static int32_t crypto_standalone_process_configure_tc(void)
{
    int32_t                    status = CRYPTO_LIB_SUCCESS;
    TCGvcidManagedParameters_t managed_parameters = {0, CRYPTO_STANDALONE_PROCESS_SCID, 0,
                                                     CRYPTO_STANDALONE_PROCESS_TC_HAS_FECF,
                                                     CRYPTO_STANDALONE_PROCESS_TC_HAS_SEG_HDRS,
                                                     TC_MAX_FRAME_SIZE, 1};
    SecurityAssociation_t     *sa_ptr = NULL;

    memset(tc_gvcid_managed_parameters_array, 0, sizeof(tc_gvcid_managed_parameters_array));
    tc_gvcid_counter = 0;

    status = Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_NO_PUS_HDR,
                              tc_ignore_anti_replay, TC_IGNORE_SA_STATE_FALSE,
                              TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                              SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }


    managed_parameters.vcid = 2;
    status                  = Crypto_Config_Add_TC_Gvcid_Managed_Parameters(managed_parameters);
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
        sa_ptr->gvcid_blk.scid  = CRYPTO_STANDALONE_PROCESS_SCID;
        sa_ptr->gvcid_blk.vcid  = 3;
        sa_ptr->gvcid_blk.mapid = TYPE_TC;
    }
    if (sa_if->sa_get_from_spi(4, &sa_ptr) == CRYPTO_LIB_SUCCESS)
    {
        sa_ptr->sa_state        = SA_OPERATIONAL;
        sa_ptr->gvcid_blk.scid  = CRYPTO_STANDALONE_PROCESS_SCID;
        sa_ptr->gvcid_blk.vcid  = 2;
        sa_ptr->gvcid_blk.mapid = TYPE_TC;
        sa_ptr->arsn_len        = 0;
    }

    return status;
}

static int32_t crypto_standalone_process_reset(void)
{
    int32_t status;

    status = Crypto_Shutdown();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib shutdown failed with error %d \n", status);
    }

    status = Crypto_SC_Init();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
        return status;
    }

    status = crypto_standalone_process_configure_tc();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib TC process configuration failed with error %d \n", status);
    }

    return status;
}

static int32_t crypto_standalone_process_tc_frame(TC_t *in_data, uint8_t *out_data, uint16_t *out_length)
{
    uint8_t  segment_hdr_len = tc_current_managed_parameters_struct.has_segmentation_hdr ? TC_SEGMENT_HDR_SIZE : 0;
    uint8_t  fecf_len        = tc_current_managed_parameters_struct.has_fecf ? FECF_SIZE : 0;
    uint16_t write_index     = TC_FRAME_HEADER_SIZE;
    uint16_t frame_length;
    uint16_t fecf;

    frame_length = TC_FRAME_HEADER_SIZE + segment_hdr_len + in_data->tc_pdu_len + fecf_len;
    if (frame_length > TC_MAX_FRAME_SIZE)
    {
        return CRYPTO_LIB_ERROR;
    }
    *out_length = frame_length;

    out_data[0] = ((in_data->tc_header.tfvn << 6) & 0xC0) | ((in_data->tc_header.bypass << 5) & 0x20) |
                  ((in_data->tc_header.cc << 4) & 0x10) | ((in_data->tc_header.spare << 2) & 0x0C) |
                  ((in_data->tc_header.scid >> 8) & 0x03);
    out_data[1] = in_data->tc_header.scid & 0xFF;
    out_data[2] = ((in_data->tc_header.vcid << 2) & 0xFC) | (((frame_length - 1) >> 8) & 0x03);
    out_data[3] = (frame_length - 1) & 0xFF;
    out_data[4] = in_data->tc_header.fsn;

    if (segment_hdr_len > 0)
    {
        out_data[write_index] = in_data->tc_sec_header.sh;
        write_index++;
    }

    memcpy(out_data + write_index, in_data->tc_pdu, in_data->tc_pdu_len);
    write_index += in_data->tc_pdu_len;

    if (fecf_len > 0)
    {
        fecf                        = Crypto_Calc_FECF(out_data, write_index);
        out_data[write_index]       = (fecf >> 8) & 0xFF;
        out_data[write_index + 1]   = fecf & 0xFF;
    }

    return CRYPTO_LIB_SUCCESS;
}

void crypto_standalone_process_cleanup(const int signal)
{
    if (signal == SIGINT)
    {
        printf("\n");
        printf("Received CTRL+C, cleaning up... \n");
    }
    keepRunning = CRYPTO_LIB_ERROR;
    exit(signal);
}

int main(int argc, char *argv[])
{
    int32_t         status = CRYPTO_LIB_SUCCESS;
    udp_interface_t tc_process;
    uint8_t         tc_process_in[TC_MAX_FRAME_SIZE];
    uint8_t         tc_process_out[TC_MAX_FRAME_SIZE];
    TC_t            tc_frame;
    int             tc_process_len = 0;
    uint16_t        tc_out_len     = 0;
    pthread_t       status_thread;
    crypto_standalone_status_reporter_args_t status_args;

    tc_process.read.ip_address  = CRYPTOLIB_HOSTNAME;
    tc_process.read.port        = TC_PROCESS_PORT;
    tc_process.write.ip_address = GSW_HOSTNAME;
    tc_process.write.port       = TC_PROCESS_FWD_PORT;
    status_args.write_sock      = &tc_process.write;
    status_args.tracker         = &tc_status;
    status_args.attempt_label   = "process";
    status_args.keep_running    = &keepRunning;
    status_args.use_tcp         = 0;

    printf("Starting CryptoLib in standalone TC process mode! \n");
    status = crypto_standalone_process_parse_args(argc, argv);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        exit(EXIT_FAILURE);
    }
    printf("TC anti-replay mode: %s\n", crypto_standalone_process_anti_replay_mode());

    signal(SIGINT, crypto_standalone_process_cleanup);

    status = crypto_standalone_process_use_state_dir();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        keepRunning = CRYPTO_LIB_ERROR;
    }

    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = crypto_standalone_process_reset();
        if (status != CRYPTO_LIB_SUCCESS)
        {
            keepRunning = CRYPTO_LIB_ERROR;
        }
    }

    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = crypto_standalone_process_socket_init(&tc_process.read, TC_PROCESS_PORT, 1);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            printf("crypto_standalone_process_socket_init tc_process.read failed with status %d \n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
        else
        {
            status = crypto_standalone_process_socket_init(&tc_process.write, TC_PROCESS_FWD_PORT, 0);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                printf("crypto_standalone_process_socket_init tc_process.write failed with status %d \n", status);
                keepRunning = CRYPTO_LIB_ERROR;
            }
        }
    }

    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        printf("  TC Process \n");
        printf("    Read, UDP - %s : %d \n", tc_process.read.ip_address, tc_process.read.port);
        printf("    Write, UDP - %s : %d \n", tc_process.write.ip_address, tc_process.write.port);
        printf("\n");

        status = pthread_create(&status_thread, NULL, *crypto_standalone_status_reporter, &status_args);
        if (status != 0)
        {
            printf("Failed to create status_thread thread: %d\n", status);
        }
        else
        {
            pthread_detach(status_thread);
        }
    }

    memset(tc_process_in, 0x00, sizeof(tc_process_in));
    memset(tc_process_out, 0x00, sizeof(tc_process_out));

    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {

        printf("\ncrypto_config_tc.ignore_anti_replay btw: %d", crypto_config_tc.ignore_anti_replay);
        struct sockaddr_in source_address;
        socklen_t          source_address_len = sizeof(source_address);

        status = recvfrom(tc_process.read.sockfd, tc_process_in, sizeof(tc_process_in), 0,
                          (struct sockaddr *)&source_address, &source_address_len);
        if (status != -1)
        {
            uint8_t control_request_handled = CRYPTO_FALSE;
            uint8_t tc_frame_vcid = 0;
            uint16_t input_len;

            tc_process_len = status;
            input_len      = (uint16_t)tc_process_len;
            status = crypto_standalone_process_handle_anti_replay_enforcement_request(
                tc_process.write.sockfd, &tc_process.write.saddr, tc_process_in, input_len, &control_request_handled);
            if (control_request_handled == CRYPTO_TRUE)
            {
                if (status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_process - Anti-replay enforcement reply error %d \n", status);
                }
                memset(tc_process_in, 0x00, sizeof(tc_process_in));
                tc_process_len = 0;
                continue;
            }

            status = crypto_standalone_handle_counter_set_request(tc_process.write.sockfd, &tc_process.write.saddr,
                                                                  tc_process_in, input_len, 0,
                                                                  &control_request_handled);
            if (control_request_handled == CRYPTO_TRUE)
            {
                if (status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_process - Counter set reply error %d \n", status);
                }
                memset(tc_process_in, 0x00, sizeof(tc_process_in));
                tc_process_len = 0;
                continue;
            }

            if (tc_debug == 1)
            {
                printf("crypto_standalone_tc_process - received[%d]: 0x", tc_process_len);
                for (int i = 0; i < tc_process_len; i++)
                {
                    printf("%02x", tc_process_in[i]);
                }
                printf("\n");
            }

            status = crypto_standalone_process_get_tc_vcid(tc_process_in, (uint16_t)tc_process_len, &tc_frame_vcid);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                int32_t reply_status;
                printf("crypto_standalone_tc_process - dropping short TC frame\n");
                reply_status = crypto_standalone_send_envelope(tc_process.write.sockfd, &tc_process.write.saddr,
                                                               tc_process_in, input_len, NULL, 0, status, 0);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_process - Reply error %d \n", reply_status);
                }
                continue;
            }

            if (crypto_standalone_process_vcid_requires_security(tc_frame_vcid) == 0)
            {
                int32_t reply_status;
                crypto_standalone_note_attempt(&tc_status, tc_frame_vcid, CRYPTO_LIB_SUCCESS);
                reply_status =
                    crypto_standalone_send_envelope(tc_process.write.sockfd, &tc_process.write.saddr, tc_process_in,
                                                    input_len, tc_process_in, input_len, CRYPTO_LIB_SUCCESS, 0);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_process - Reply error %d \n", reply_status);
                }
                continue;
            }

            memset(&tc_frame, 0x00, sizeof(tc_frame));
            status = Crypto_TC_ProcessSecurity(tc_process_in, &tc_process_len, &tc_frame);
            if (status == CRYPTO_LIB_SUCCESS)
            {
                status = crypto_standalone_process_tc_frame(&tc_frame, tc_process_out, &tc_out_len);
            }
            crypto_standalone_note_attempt(&tc_status, tc_frame_vcid, status);

            if (status == CRYPTO_LIB_SUCCESS)
            {
                if (tc_debug == 1)
                {
                    printf("crypto_standalone_tc_process - status = %d, decrypted[%d]: 0x", status, tc_out_len);
                    for (int i = 0; i < tc_out_len; i++)
                    {
                        printf("%02x", tc_process_out[i]);
                    }
                    printf("\n");
                }
                int32_t reply_status;
                reply_status =
                    crypto_standalone_send_envelope(tc_process.write.sockfd, &tc_process.write.saddr, tc_process_in,
                                                    input_len, tc_process_out, tc_out_len, CRYPTO_LIB_SUCCESS, 0);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_process - Reply error %d \n", reply_status);
                }
            }
            else
            {
                int32_t reply_status;
                printf("crypto_standalone_tc_process - ProcessSecurity error %d \n", status);
                reply_status = crypto_standalone_send_envelope(tc_process.write.sockfd, &tc_process.write.saddr,
                                                               tc_process_in, input_len, NULL, 0, status, 0);
                if (reply_status != CRYPTO_LIB_SUCCESS)
                {
                    printf("crypto_standalone_tc_process - Reply error %d \n", reply_status);
                }
            }

            memset(tc_process_in, 0x00, sizeof(tc_process_in));
            memset(tc_process_out, 0x00, sizeof(tc_process_out));
            tc_process_len = 0;
            tc_out_len     = 0;
        }

        usleep(100);
    }

    close(tc_process.read.sockfd);
    close(tc_process.write.sockfd);
    Crypto_Shutdown();

    printf("\n");
    exit(status);
}

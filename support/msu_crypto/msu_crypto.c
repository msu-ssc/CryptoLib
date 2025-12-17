#include "crypto.h"
#include "crypto_config_structs.h"
#include "crypto_error.h"
#include "key_interface.h"
#include "sa_interface.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_SPI 1
#define DEFAULT_SCID 0x0003
#define DEFAULT_VCID 0
#define DEFAULT_KEY_ID 1
#define DEFAULT_TFVN 0

#define KEY_STORE_PATH ".msu_crypto_key"

typedef struct
{
    int      register_key;
    int      encrypt;
    int      decrypt;
    int      tc_frame;
    int      space_packet;
    uint16_t spi;
    uint16_t scid;
    uint8_t  vcid;
    uint16_t key_id;
    const char *key_hex;
    const char *key_store_path;
} cli_opts_t;

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s --register-key <hexkey> [--key-id N] [--key-store <path>]\n"
            "  %s --encrypt (--tc-frame | --space-packet) [--spi N] [--scid N] [--vcid N] [--key-id N] [--key-hex <hex>] "
            "[--key-store <path>]\n"
            "  %s --decrypt --tc-frame [--spi N] [--scid N] [--vcid N] [--key-id N] [--key-hex <hex>] "
            "[--key-store <path>]\n"
            "\n"
            "Notes:\n"
            "  - Input is read from STDIN; output is written to STDOUT.\n"
            "  - Keys must be 16 or 32 bytes, provided as hex (no 0x prefix).\n"
            "  - Decrypt writes the recovered TC PDU bytes (not the full frame headers) to STDOUT.\n"
            "  - --space-packet wraps the input as a TC frame (no segmentation header) before encrypting.\n",
            prog, prog, prog);
}

static int parse_hex(const char *hex, uint8_t *out, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
    {
        return -1;
    }
    size_t bytes = hex_len / 2;
    for (size_t i = 0; i < bytes; i++)
    {
        unsigned int val = 0;
        if (sscanf(&hex[i * 2], "%2x", &val) != 1)
        {
            return -1;
        }
        out[i] = (uint8_t)val;
    }
    *out_len = bytes;
    return 0;
}

static const char *get_default_store_path(char *buf, size_t buf_len)
{
    const char *home = getenv("HOME");
    if (home != NULL)
    {
        snprintf(buf, buf_len, "%s/%s", home, KEY_STORE_PATH);
        return buf;
    }
    return KEY_STORE_PATH;
}

static int save_key_hex(const char *path, const char *hex)
{
    FILE *f = fopen(path, "w");
    if (!f)
    {
        return -1;
    }
    if (fprintf(f, "%s\n", hex) < 0)
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int load_key_hex(const char *path, char *hex_buf, size_t hex_buf_len)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        return -1;
    }
    if (!fgets(hex_buf, (int)hex_buf_len, f))
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t len = strlen(hex_buf);
    while (len > 0 && (hex_buf[len - 1] == '\n' || hex_buf[len - 1] == '\r'))
    {
        hex_buf[--len] = '\0';
    }
    return 0;
}

static int read_stdin(uint8_t **out, size_t *out_len)
{
    size_t      cap = 4096;
    size_t      len = 0;
    uint8_t    *buf = malloc(cap);
    if (!buf)
    {
        return -1;
    }
    while (!feof(stdin))
    {
        if (len == cap)
        {
            cap *= 2;
            uint8_t *tmp = realloc(buf, cap);
            if (!tmp)
            {
                free(buf);
                return -1;
            }
            buf = tmp;
        }
        size_t n = fread(buf + len, 1, cap - len, stdin);
        len += n;
        if (n == 0)
        {
            break;
        }
    }
    *out     = buf;
    *out_len = len;
    return 0;
}

static int configure_and_init(uint16_t scid, uint8_t vcid, uint16_t spi, uint16_t key_id, const uint8_t *key,
                              size_t key_len)
{
    int32_t status = Crypto_Config_CryptoLib(
        KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, IV_INTERNAL,
        CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_TRUE,
        TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_FALSE, 0x3F,
        SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        fprintf(stderr, "Crypto_Config_CryptoLib failed (%d)\n", status);
        return -1;
    }

    GvcidManagedParameters_t mp = {0};
    mp.tfvn                     = DEFAULT_TFVN;
    mp.scid                     = scid;
    mp.vcid                     = vcid;
    mp.has_fecf                 = TC_HAS_FECF;
    mp.aos_has_fhec             = AOS_FHEC_NA;
    mp.aos_has_iz               = AOS_IZ_NA;
    mp.aos_iz_len               = 0;
    mp.has_segmentation_hdr     = TC_NO_SEGMENT_HDRS;
    mp.max_frame_size           = TC_MAX_FRAME_SIZE;
    mp.has_ocf                  = TC_OCF_NA;
    mp.set_flag                 = 1;
    status                      = Crypto_Config_Add_Gvcid_Managed_Parameters(mp);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        fprintf(stderr, "Crypto_Config_Add_Gvcid_Managed_Parameters failed (%d)\n", status);
        return -1;
    }

    status = Crypto_Init();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        fprintf(stderr, "Crypto_Init failed (%d)\n", status);
        return -1;
    }

    KeyInterface key_if = get_key_interface_internal();
    crypto_key_t *k     = key_if->get_key(key_id);
    if (!k)
    {
        fprintf(stderr, "Failed to fetch key slot %u\n", key_id);
        return -1;
    }
    if (key_len > KEY_SIZE)
    {
        fprintf(stderr, "Key too long (%zu bytes)\n", key_len);
        return -1;
    }
    memset(k->value, 0, KEY_SIZE);
    memcpy(k->value, key, key_len);
    k->key_len   = (uint32_t)key_len;
    k->key_state = KEY_ACTIVE;

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *sa_ptr;
    status = sa_if->sa_get_from_spi(spi, &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS || sa_ptr == NULL)
    {
        fprintf(stderr, "Failed to obtain SA for SPI %u (%d)\n", spi, status);
        return -1;
    }

    memset(sa_ptr, 0, sizeof(SecurityAssociation_t));
    sa_ptr->spi            = spi;
    sa_ptr->ekid           = key_id;
    sa_ptr->akid           = key_id;
    sa_ptr->sa_state       = SA_OPERATIONAL;
    sa_ptr->gvcid_blk.tfvn = DEFAULT_TFVN;
    sa_ptr->gvcid_blk.scid = scid;
    sa_ptr->gvcid_blk.vcid = vcid;
    sa_ptr->gvcid_blk.mapid = 0;
    sa_ptr->est             = 1;
    sa_ptr->ast             = 0; // encryption only (no separate auth bitmask requirement)
    sa_ptr->ecs             = CRYPTO_CIPHER_AES256_GCM;
    sa_ptr->ecs_len         = 1;
    sa_ptr->acs             = CRYPTO_MAC_NONE;
    sa_ptr->acs_len         = 0;
    sa_ptr->shivf_len       = 12;
    sa_ptr->iv_len          = 12;
    memset(sa_ptr->iv, 0, sizeof(sa_ptr->iv));
    sa_ptr->stmacf_len = 0;
    sa_ptr->shsnf_len  = 0;
    sa_ptr->shplf_len  = 0;
    sa_ptr->abm_len    = 0;
    sa_ptr->arsn_len   = 0;
    sa_ptr->arsnw_len  = 0;
    sa_ptr->arsnw      = 0;

    status = sa_if->sa_save_sa(sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        fprintf(stderr, "sa_save_sa failed (%d)\n", status);
        return -1;
    }

    return 0;
}

static int handle_encrypt(const cli_opts_t *opts)
{
    char key_hex_buf[KEY_SIZE * 2 + 2] = {0};
    const char *hex                    = opts->key_hex;
    if (!hex)
    {
        if (load_key_hex(opts->key_store_path, key_hex_buf, sizeof(key_hex_buf)) != 0)
        {
            fprintf(stderr, "Failed to load key from %s\n", opts->key_store_path);
            return -1;
        }
        hex = key_hex_buf;
    }

    uint8_t key_bytes[KEY_SIZE] = {0};
    size_t  key_len             = 0;
    if (parse_hex(hex, key_bytes, &key_len) != 0 || !(key_len == 16 || key_len == 32))
    {
        fprintf(stderr, "Key must be 16 or 32 bytes of hex\n");
        return -1;
    }

    uint8_t *input     = NULL;
    size_t   input_len = 0;
    if (read_stdin(&input, &input_len) != 0)
    {
        fprintf(stderr, "Failed to read stdin\n");
        return -1;
    }

    if (input_len > UINT16_MAX)
    {
        fprintf(stderr, "Input too large (%zu bytes)\n", input_len);
        free(input);
        return -1;
    }

    if (configure_and_init(opts->scid, opts->vcid, opts->spi, opts->key_id, key_bytes, key_len) != 0)
    {
        free(input);
        return -1;
    }

    uint8_t *frame_buf      = input;
    uint16_t frame_buf_len  = (uint16_t)input_len;
    uint8_t *allocated_buf  = NULL;
    static uint8_t fsn_ctr  = 0;

    if (opts->space_packet)
    {
        // Wrap the payload as a TC frame (no segmentation header), with FECF space reserved.
        size_t total_len = TC_FRAME_HEADER_SIZE + input_len + FECF_SIZE;
        if (total_len > UINT16_MAX)
        {
            fprintf(stderr, "Wrapped frame too large (%zu bytes)\n", total_len);
            free(input);
            return -1;
        }
        allocated_buf = malloc(total_len);
        if (!allocated_buf)
        {
            fprintf(stderr, "Failed to allocate frame buffer\n");
            free(input);
            return -1;
        }
        memset(allocated_buf, 0, total_len);

        uint16_t fl_field = (uint16_t)(total_len - 1); // frame length field = total_octets - 1
        uint16_t scid     = opts->scid & 0x03FF;
        uint8_t  vcid     = opts->vcid & 0x3F;

        // Byte 0: tfvn(2) | bypass(1)=0 | cc(1)=0 | spare(2)=0 | scid[9:8]
        allocated_buf[0] = (uint8_t)((DEFAULT_TFVN & 0x03) << 6) | (uint8_t)((scid >> 8) & 0x03);
        // Byte 1: scid[7:0]
        allocated_buf[1] = (uint8_t)(scid & 0xFF);
        // Byte 2: vcid[5:0] | fl[9:8]
        allocated_buf[2] = (uint8_t)((vcid & 0x3F) << 2) | (uint8_t)((fl_field >> 8) & 0x03);
        // Byte 3: fl[7:0]
        allocated_buf[3] = (uint8_t)(fl_field & 0xFF);
        // Byte 4: fsn
        allocated_buf[4] = fsn_ctr++;

        memcpy(allocated_buf + TC_FRAME_HEADER_SIZE, input, input_len);
        // FECF placeholder already zeroed by memset

        frame_buf     = allocated_buf;
        frame_buf_len = (uint16_t)total_len;
    }

    uint8_t *out_buf      = NULL;
    uint16_t out_buf_size = 0;
    int32_t  status =
        Crypto_TC_ApplySecurity(frame_buf, frame_buf_len, &out_buf, &out_buf_size);
    free(input);
    free(allocated_buf);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        fprintf(stderr, "Crypto_TC_ApplySecurity failed (%d)\n", status);
        return -1;
    }

    fwrite(out_buf, 1, out_buf_size, stdout);
    Crypto_TC_Safe_Free_Ptr(out_buf);
    return 0;
}

static int handle_decrypt(const cli_opts_t *opts)
{
    char key_hex_buf[KEY_SIZE * 2 + 2] = {0};
    const char *hex                    = opts->key_hex;
    if (!hex)
    {
        if (load_key_hex(opts->key_store_path, key_hex_buf, sizeof(key_hex_buf)) != 0)
        {
            fprintf(stderr, "Failed to load key from %s\n", opts->key_store_path);
            return -1;
        }
        hex = key_hex_buf;
    }

    uint8_t key_bytes[KEY_SIZE] = {0};
    size_t  key_len             = 0;
    if (parse_hex(hex, key_bytes, &key_len) != 0 || !(key_len == 16 || key_len == 32))
    {
        fprintf(stderr, "Key must be 16 or 32 bytes of hex\n");
        return -1;
    }

    uint8_t *input     = NULL;
    size_t   input_len = 0;
    if (read_stdin(&input, &input_len) != 0)
    {
        fprintf(stderr, "Failed to read stdin\n");
        return -1;
    }
    if (input_len > INT_MAX)
    {
        fprintf(stderr, "Input too large (%zu bytes)\n", input_len);
        free(input);
        return -1;
    }
    int len_ingest = (int)input_len;

    if (configure_and_init(opts->scid, opts->vcid, opts->spi, opts->key_id, key_bytes, key_len) != 0)
    {
        free(input);
        return -1;
    }

    TC_t    tc_frame = (TC_t){0};
    int32_t status   = Crypto_TC_ProcessSecurity(input, &len_ingest, &tc_frame);
    free(input);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        fprintf(stderr, "Crypto_TC_ProcessSecurity failed (%d)\n", status);
        return -1;
    }

    fwrite(tc_frame.tc_pdu, 1, tc_frame.tc_pdu_len, stdout);
    return 0;
}

static int parse_args(int argc, char **argv, cli_opts_t *opts)
{
    opts->register_key   = 0;
    opts->encrypt        = 0;
    opts->decrypt        = 0;
    opts->tc_frame       = 0;
    opts->space_packet   = 0;
    opts->spi            = DEFAULT_SPI;
    opts->scid           = DEFAULT_SCID;
    opts->vcid           = DEFAULT_VCID;
    opts->key_id         = DEFAULT_KEY_ID;
    opts->key_hex        = NULL;
    opts->key_store_path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--register-key") == 0 && i + 1 < argc)
        {
            opts->register_key = 1;
            opts->key_hex      = argv[++i];
        }
        else if (strcmp(argv[i], "--encrypt") == 0)
        {
            opts->encrypt = 1;
        }
        else if (strcmp(argv[i], "--decrypt") == 0)
        {
            opts->decrypt = 1;
        }
        else if (strcmp(argv[i], "--tc-frame") == 0)
        {
            opts->tc_frame = 1;
        }
        else if (strcmp(argv[i], "--space-packet") == 0)
        {
            opts->space_packet = 1;
        }
        else if (strcmp(argv[i], "--spi") == 0 && i + 1 < argc)
        {
            opts->spi = (uint16_t)strtoul(argv[++i], NULL, 0);
        }
        else if (strcmp(argv[i], "--scid") == 0 && i + 1 < argc)
        {
            opts->scid = (uint16_t)strtoul(argv[++i], NULL, 0);
        }
        else if (strcmp(argv[i], "--vcid") == 0 && i + 1 < argc)
        {
            opts->vcid = (uint8_t)strtoul(argv[++i], NULL, 0);
        }
        else if (strcmp(argv[i], "--key-id") == 0 && i + 1 < argc)
        {
            opts->key_id = (uint16_t)strtoul(argv[++i], NULL, 0);
        }
        else if (strcmp(argv[i], "--key-hex") == 0 && i + 1 < argc)
        {
            opts->key_hex = argv[++i];
        }
        else if (strcmp(argv[i], "--key-store") == 0 && i + 1 < argc)
        {
            opts->key_store_path = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0)
        {
            return -1;
        }
        else
        {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return -1;
        }
    }

    if (opts->register_key + opts->encrypt + opts->decrypt != 1)
    {
        fprintf(stderr, "Specify exactly one of --register-key, --encrypt, or --decrypt\n");
        return -1;
    }
    if ((opts->encrypt || opts->decrypt) && !(opts->tc_frame || opts->space_packet))
    {
        fprintf(stderr, "Specify one of --tc-frame or --space-packet\n");
        return -1;
    }
    if (opts->tc_frame && opts->space_packet)
    {
        fprintf(stderr, "Choose only one: --tc-frame or --space-packet\n");
        return -1;
    }

    if (!opts->key_store_path)
    {
        static char store_path[512];
        opts->key_store_path = get_default_store_path(store_path, sizeof(store_path));
    }

    return 0;
}

int main(int argc, char **argv)
{
    cli_opts_t opts;
    if (parse_args(argc, argv, &opts) != 0)
    {
        print_usage(argv[0]);
        return 1;
    }

    if (opts.register_key)
    {
        if (!opts.key_hex)
        {
            fprintf(stderr, "Missing key hex for registration\n");
            return 1;
        }
        uint8_t key_bytes[KEY_SIZE];
        size_t  key_len = 0;
        if (parse_hex(opts.key_hex, key_bytes, &key_len) != 0 || !(key_len == 16 || key_len == 32))
        {
            fprintf(stderr, "Key must be 16 or 32 bytes of hex\n");
            return 1;
        }
        if (save_key_hex(opts.key_store_path, opts.key_hex) != 0)
        {
            fprintf(stderr, "Failed to save key to %s (%s)\n", opts.key_store_path, strerror(errno));
            return 1;
        }
        return 0;
    }

    if (opts.encrypt)
    {
        return handle_encrypt(&opts);
    }
    else
    {
        return handle_decrypt(&opts);
    }
}

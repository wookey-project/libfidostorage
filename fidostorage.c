#include "libc/nostd.h"
#include "libc/string.h"
#include "api/libfidostorage.h"
#include "fidostorage.h"
#include "sd_enc.h"

#define AES_KEY_LEN 32
#define HMAC_KEY_LEN 32

/**********************************************************
 * About storage structure header definition keept private)
 */
typedef enum {
    SLOTID_FREE     = 0x15e4f8a6UL,
    SLOTID_USED     = 0x7f180654UL
} fidostorage_appid_table_flag_t;


typedef struct {
    uint8_t     *buf;
    uint16_t     buflen;
    uint8_t      key[AES_KEY_LEN];
    uint32_t     key_len;
    uint8_t      hmac_key[HMAC_KEY_LEN];
    bool         configured;
} fidostorage_ctx_t;


/*
 * appid table struct
 */
typedef struct __packed {
    uint8_t     appid[32];                  /*< application identifier */
    uint32_t    slotid;                     /*< slot identifier, corresponding to sector identifier in SDCard
                                                where the appid infos are written */
    uint8_t     hmac[32];                   /*< appid slot HMAC        */
    uint8_t     padding[SECTOR_SIZE - 68];  /*< padding to sector size */
} fidostorage_appid_table_t;

/*
 * Specify the effective SDCard header structure (size 4096 bytes).
 * This structure simplify the access to the first crypto sector.
 * The appid_table is not mapped in the structure (0-sized) but yet declared.
 */
typedef struct __packed {
    uint8_t     bitmap[SLOT_NUM / 8];                   /*< list of activated/unactivated slots (bitmap): size: 1k (2 sectors) */
    uint8_t     hmac[32];                               /*< HMAC for the overall fifodstorage_header_t */
    uint8_t     hmac_padding[SECTOR_SIZE - 32];         /*< HMAC padding with zeros */
    uint8_t     crypto_sector_padding[5*SECTOR_SIZE];   /*< padding to align appid_table to 4k */
    fidostorage_appid_table_t   appid_table[0];         /*< table of all appid header (se above) */
} fidostorage_header_t;

static fidostorage_ctx_t ctx = { 0 };

/**********************************************************
 * local utility functions
 */

static inline bool fidostorage_is_configured(void) {
    return (ctx.configured == true);
}

static inline mbed_error_t fidostorage_get_hmac_key_from_master(uint8_t *master, uint8_t *key_h, uint32_t *keylen) {
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (master == NULL || key_h == NULL || keylen == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    // K = SHA-256("INTEGRITY"+K_M)
    const char *integrity = "INTEGRITY";
    sha256_context sha256_ctx;
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (const unsigned char*)integrity, strlen(integrity));
    sha256_update(&sha256_ctx, master, 32);
    sha256_final(&sha256_ctx, key_h);
    *keylen = 32;

    printf("HMAC key is: ");
    hexdump(key_h, 32);
err:
    return errcode;
}

static inline mbed_error_t fidostorage_get_aes_key_from_master(uint8_t *master, uint8_t *key_aes, uint32_t *keylen) {
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (master == NULL || key_aes == NULL || keylen == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    // K = SHA-256("ENCRYPTION"+K_M)
    const char *encryption = "ENCRYPTION";
    sha256_context sha256_ctx;
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (const unsigned char*)encryption, strlen(encryption));
    sha256_update(&sha256_ctx, master, 32);
    sha256_final(&sha256_ctx, key_aes);
    *keylen = 32;

    log_printf("AES key is: ");
    hexdump(key_aes, 32);
err:
    return errcode;
}


/**********************************************************
 * init, configure library
 */

mbed_error_t fidostorage_declare(void)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    errcode = sd_enc_declare();
    return errcode;
}

/*@
  @ requires \separated(black_buf + (0 .. buflen-1),red_buf + (0 .. buflen-1),&ctx);
 */
mbed_error_t    fidostorage_configure(uint8_t *buf, uint16_t  buflen, uint8_t *master_key)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* we wish to read from the appid table list at least 4 appid slot identifier at a time,
     * for performance constraints */
    uint16_t minsize = 4096;

    if (buf == NULL || buflen == 0) {
        log_printf("[fidostorage] configure: invalid params\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (buflen < minsize) {
        log_printf("[fidostorage] configure: buffer too small, should be at least %d bytes len\n", minsize);
        errcode = MBED_ERROR_NOMEM;
        goto err;
    }
    ctx.buf = buf;
    ctx.buflen = 4096; /* minsize */
    /* set storage key */
    memcpy(&ctx.key[0], master_key, 32);
    /* Derive our AES key */
    uint8_t aes_key[32];
    uint32_t keylen = sizeof(aes_key);
    if ((errcode = fidostorage_get_aes_key_from_master(master_key, aes_key, &keylen)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] failed while setting encryption key\n");
        goto err;
    }

    if ((errcode = set_encrypted_SD_key(aes_key, sizeof(aes_key))) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] failed while setting encryption key in SD layer\n");
        goto err;
    }
    keylen = sizeof(ctx.hmac_key);
    if ((errcode = fidostorage_get_hmac_key_from_master(master_key, &ctx.hmac_key[0], &keylen)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] failed while setting integrity key\n");
        goto err;
    }
    ctx.configured = true;
    request_data_membarrier();
err:
    return errcode;
}

/**********************************************************
 * Manipulate storage content
 */

/* appid is 32 bytes len identifier */
mbed_error_t    fidostorage_get_appid_slot(uint8_t const * const appid, uint32_t *slotid, uint8_t *hmac)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* get back buflen (in bytes), convert to words. buflen is already word multiple */
    /* INFO: this is an optimization here as we read more than one sector at a time, and check
     * multiple appid table lines in the buffer before reading and decrypting another buffer */
    uint32_t curr_sector = 0; /* this variable handle crypto sectors (i.e. 4K sized) */
    /* slotting table HMAC, to be read and calculated */
    hmac_context hmac_ctx;
    uint8_t  calculated_hmac[32];
    uint8_t  header_hmac[32];
    uint32_t hmac_len = 32;


    if (!fidostorage_is_configured()) {
        log_printf("[fidostorage] not yet configured!\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || slotid == NULL || hmac == NULL) {
        log_printf("[fidostorage] invalid param !\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);
#endif

    /* initialize HMAC calculation */
    hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);

    /* we start from sector 0, to get back the bitmap and the HMAC */
    if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] failed while reading bitmap and HMAC\n");
        goto err;
    }
    /* get back HMAC */
    fidostorage_header_t *header = (fidostorage_header_t*)&ctx.buf[0];
    memcpy(header_hmac, &header->hmac[0], 32);
    /* TODO: handle bitmap */

    /* starting HMAC calculation */
    hmac_update(&hmac_ctx, header->bitmap, 1024);

    /* now reading the effective */
    curr_sector++;
    bool slot_found = false;
    /* looping on slotting table, reading 8 cells each time */
    while (curr_sector <= (SLOT_NUM/8)) {
        //log_printf("[fidostorage] reading %d bytes starting from (crypto) sector %x (@[bytes]: %d\n", ctx.buflen, curr_sector, curr_sector*SLOT_SIZE);
        /* INFO: sd_read address argument is **sector address**. Sectors are 512 bytes len (same len as
         * fidostorage_appid_table_t cells).
         */

        if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, curr_sector)) != MBED_ERROR_NONE) {
            log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", curr_sector, errcode);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        uint16_t numcell = 8; /* there are 8 cells per 4k read (512 bytes per cell) */

        fidostorage_appid_table_t   *appid_table = (fidostorage_appid_table_t*)&ctx.buf[0];
        for (uint16_t j = 0; j < numcell; j++) {
            /* does current cell appid matches ? */
            if (memcmp(appid_table[j].appid, appid, 32) == 0) {
                log_printf("[fidostorage] found appid ! slot is 0x%x\n", appid_table[j].slotid);
                /* appid matches ! return slot id and slot HMAC */
                *slotid = appid_table[j].slotid;
                memcpy(hmac, &appid_table[j].hmac, sizeof(appid_table[j].hmac));
                slot_found = true;
            }
            /* update calculated HMAC */
            hmac_update(&hmac_ctx, &appid_table[j].appid[0], sizeof(appid_table[j].appid) + sizeof(appid_table[j].slotid) + sizeof(appid_table[j].hmac));
        }
        curr_sector++;
    }
    hmac_finalize(&hmac_ctx, &calculated_hmac[0], &hmac_len);
#if CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
    log_printf("Header HMAC read on SD:\n");
    hexdump(header_hmac, 32);
    log_printf("Header calculated HMAC:\n");
    hexdump(calculated_hmac, hmac_len);
#endif
    if (memcmp(&header_hmac[0], &calculated_hmac[0], hmac_len) != 0) {
        log_printf("[logstorage] slot table integrity check failed !\n");
#if 0
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
#endif
    }
    if (slot_found != true) {
        /* appid not found !*/
        log_printf("[fidostorage] appid not found\n");
        errcode = MBED_ERROR_NOTFOUND;
    }

err:
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    log_printf("[fidostorage] took %d ms to read, uncrypt and parse %d bytes from uSD\n", (uint32_t)(ms2-ms1), (curr_sector-1)*SLOT_SIZE);
    log_printf("[fidostorage] %d loops executed\n", (curr_sector-1));
#endif
    return errcode;
}


mbed_error_t    fidostorage_register_appid(uint8_t const * const appid, uint32_t  * const slotid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || slotid == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }


err:
    return errcode;
}

mbed_error_t    fidostorage_get_appid_metadata(uint8_t const * const     appid,
                                               uint32_t const            slotid,
                                               uint8_t const *           appid_slot_hmac,
                                               fidostorage_appid_slot_t *data_buffer)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || data_buffer == NULL || appid_slot_hmac == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);
#endif

    if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], SLOT_SIZE, (SECTOR_SIZE * slotid) / SLOT_SIZE)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", (SECTOR_SIZE * slotid) / SLOT_SIZE, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    fidostorage_appid_slot_t *mt = (fidostorage_appid_slot_t*)&data_buffer[0];

    /* is appid for this slot id match the one given ? */
    if (memcmp(appid, mt->appid, 32) != 0) {
        log_printf("[fidostorage] metadata of slotid = 0x%x does not correspond to the correct appid\n", slotid);
        hexdump(appid, 32);
        hexdump(mt->appid, 32);        
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    /* overflow detection */
    if (mt->icon_type == ICON_TYPE_IMAGE &&
        mt->icon_len > (SLOT_SIZE - (sizeof(fidostorage_appid_slot_t) - sizeof(fidostorage_icon_data_t)))) {
        log_printf("[fidostorage] metadata icon len is invalid (too big)\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    /* check slot integrity */
    hmac_context hmac_ctx;
    uint8_t         hmac[32];
    uint32_t hmac_len = sizeof(hmac);


    hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);
    hmac_update(&hmac_ctx, (uint8_t*)mt, 32 + 4 + 60 + 4 + 2 + 2);
    if (mt->icon_len != 0) {
        hmac_update(&hmac_ctx, &mt->icon.icon_data[0], mt->icon_len);
    }
    hmac_finalize(&hmac_ctx, &hmac[0], &hmac_len);
#if CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
    log_printf("HMAC read on SD:\n");
    hexdump(appid_slot_hmac, 32);
    log_printf("calculated HMAC:\n");
    hexdump(hmac, hmac_len);
#endif

    if (memcmp(hmac, appid_slot_hmac, 32) != 0) {
        log_printf("[fidostorage] metadata HMAC does not match given one !!!\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    log_printf("[fidostorage] appid metadata valid !\n");
    log_printf("|--> appid: \n");
    hexdump(mt->appid, 32);
    log_printf("|--> flags:      %x\n", mt->flags);
    log_printf("|--> name:       %s\n", mt->name);
    log_printf("|--> CTR:        %ld\n", mt->ctr);
    log_printf("|--> icon_len:   %ld\n", mt->icon_len);
err:
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    log_printf("[fidostorage] metadata read, uncrypt and parsing took %d ms\n", (uint32_t)(ms2 - ms1));
#endif
    random_secure = SEC_RANDOM_SECURE;
    return errcode;
}

mbed_error_t    fidostorage_set_appid_metada(uint8_t *appid, uint32_t   appid_slot, fidostorage_appid_slot_t const * const metadata)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || metadata == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    // TODO
    //
    appid_slot = appid_slot;

err:
    return errcode;
}

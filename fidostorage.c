#include "libc/types.h"
#include "libc/random.h"
#include "libc/string.h"
#include "libc/stdio.h"
#include "libc/sync.h"
#include "libc/random.h"
#include "libc/arpa/inet.h"
#include "hmac.h"
#include "aes.h"
#include "libsd.h"
#include "libcryp.h"
#include "api/libfidostorage.h"


#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

#define APPID_METADA_SLOT_MAX 2048





typedef struct {
    uint8_t     *buf;
    uint16_t     buflen;
    uint8_t      iv[16]; /* do we consider CTR with incremental iv=0 for slot=0 ? */
    uint8_t      key[32];
    uint8_t      key_h[32];
    uint32_t     key_len;
    aes_context  aes_ctx; /* aes context */
    bool         configured;
    /* in case of CRYP with DMA usage */
    bool       dma_in_finished;
    bool       dma_out_finished;
    int        dma_in_desc;
    int        dma_out_desc;
    //
    dma_shm_t dmashm_rd;
    dma_shm_t dmashm_wr;
} fidostorage_ctx_t;


/**********************************************************
 * About storage structure header definition keeped private)
 */
typedef enum {
    SLOTID_FREE     = 0x15e4f8a6UL,
    SLOTID_USED     = 0x7f180654UL
} fidostorage_appid_table_flag_t;

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
 * Specify the effective SDCard header structure.
 * This structure MUST NOT be instanciate, as its size is ~4MB.
 * IT is used as a helper to type buffer that are read and uncyphered from
 * the SDCard
 */
typedef struct __packed {
    uint8_t     bitmap[SLOT_NUM / 8];                   /*< list of activated/unactivated slots (bitmap) */
    uint8_t     hmac[32];                               /*< HMAC for the overall fifodstorage_header_t */
    uint8_t     padding[SECTOR_SIZE - 32];              /*< padding for HMAC sector */
    fidostorage_appid_table_t   appid_table[SLOT_NUM];  /*< table of all appid header (se above) */
} fidostorage_header_t;

static fidostorage_ctx_t ctx = { 0 };

/**********************************************************
 * local utility functions
 */

static inline bool fidostorage_is_configured(void) {
    return (ctx.configured == true);
}

void dma_in_complete(uint8_t irq __attribute__((unused)), uint32_t status __attribute__((unused))) {
    ctx.dma_in_finished = true;
    request_data_membarrier();
}
void dma_out_complete(uint8_t irq __attribute__((unused)), uint32_t status __attribute__((unused))) {
    ctx.dma_out_finished = true;
    request_data_membarrier();
}

/* cryptographic sector size is 4096 */
static mbed_error_t fidostorate_get_iv_from_crypto_sector(uint32_t sector, uint8_t *key_h, uint8_t *iv, uint32_t iv_len) {
    mbed_error_t errcode = MBED_ERROR_NONE;
    //
    if (iv_len < 16) {
        log_printf("[fidostorage] IV len to small\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (iv == NULL || key_h == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    /* ESSIV is big endian */
    uint32_t big_endian_sector_number = htonl(sector);
    /* marshaling from uint32 to u[4] buffer */
    uint8_t sector_number_buff[16] = { 0 };

    sector_number_buff[0] = (big_endian_sector_number >> 0) & 0xff;
    sector_number_buff[1] = (big_endian_sector_number >> 8) & 0xff;
    sector_number_buff[2] = (big_endian_sector_number >> 16) & 0xff;
    sector_number_buff[3] = (big_endian_sector_number >> 24) & 0xff;


    /* create ESSIV from sector id */
    if (aes_init(&ctx.aes_ctx, key_h, AES256, NULL, ECB, AES_ENCRYPT, AES_SOFT_UNMASKED, NULL, NULL, -1, -1)) {
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
    /* and encrypt sector in AES-ECB */
    if (aes_exec(&ctx.aes_ctx, sector_number_buff, iv, iv_len, -1, -1)) {
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
err:
    return errcode;
}

static mbed_error_t fidostorage_get_key_from_master(uint8_t *master, uint8_t *key_h, uint32_t *keylen) {
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (master == NULL || key_h == NULL || keylen == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    // K = SHA-256("ENCRYPTION"+K_M)
    const char *encryption = "ENCRYPTION";
    sha256_context sha256_ctx;
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (const unsigned char*)encryption, 10);
    sha256_update(&sha256_ctx, master, 32);
    sha256_final(&sha256_ctx, key_h);
    *keylen = 32;

err:
    return errcode;
}



/**********************************************************
 * init, configure library
 */

mbed_error_t fidostorage_declare(void)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    errcode = cryp_early_init(true, CRYP_MAP_AUTO, CRYP_CFG, &ctx.dma_in_desc, &ctx.dma_out_desc);
    request_data_membarrier();
    return errcode;
}

/*@
  @ requires \separated(black_buf + (0 .. buflen-1),red_buf + (0 .. buflen-1),&ctx);
 */
mbed_error_t    fidostorage_configure(uint8_t *buf, uint16_t  buflen, uint8_t *aes_key)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* we wish to read from the appid table list at least 4 appid slot identifier at a time,
     * for performance constraints */
    uint16_t minsize = 8 * SECTOR_SIZE;

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
    ctx.buflen = buflen;
    /* we wish to read a multiple of the fidostorage table cell content, to avoid
     * fragmentation */
    if (ctx.buflen % sizeof (fidostorage_appid_table_t)) {
        /* align to word-sized below */
        ctx.buflen -= (ctx.buflen % sizeof (fidostorage_appid_table_t));
    }
    /* set storage key */
    memcpy(&ctx.key[0], aes_key, 32);
    fidostorage_get_key_from_master(aes_key, &ctx.key_h[0], &ctx.key_len);
    ctx.configured = true;
    request_data_membarrier();
err:
    return errcode;
}

/**********************************************************
 * Manipulate storage content
 */

/* appid is 32 bytes len identifier */
mbed_error_t    fidostorage_get_appid_slot(uint8_t const * const appid, uint32_t *slot, uint8_t *hmac)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* get back buflen (in bytes), convert to words. buflen is already word multiple */
    /* INFO: this is an optimization here as we read more than one sector at a time, and check
     * multiple appid table lines in the buffer before reading and decrypting another buffer */
    uint32_t toread = ctx.buflen / 4;
    uint32_t curr_sector = 8; /* bitmap and HMAC not read here */

#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint32_t loop_turn = 0;
#endif

    if (!fidostorage_is_configured()) {
        log_printf("[fidostorage] not yet configured!\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || slot == NULL || hmac == NULL) {
        log_printf("[fidostorage] invalid param !\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);
#endif

    /* we start from sector 3, for max SLOT_NUM slots */
    while (curr_sector < SLOT_NUM+8) {
        /* here we have to cast uint8_t * to uint32_t * because sd_read reads words. Although
         * toread variable is calculated using the uint8_t* buf len. There is no overflow. */
        //log_printf("[fidostorage] reading %d bytes starting from sector %x (@[bytes]: %d\n", ctx.buflen, curr_sector, curr_sector*SECTOR_SIZE);
        int ret;
        /* INFO: sd_read address argument is **sector address**. Sectors are 512 bytes len (same len as
         * fidostorage_appid_table_t cells).
         */
        if ((ret = sd_read((uint32_t*)&ctx.buf[0], curr_sector, toread)) != SD_SUCCESS) {
            log_printf("[fidostorage] Failed during SD_read, from sector %d, %d words to be read: ret=%d\n", curr_sector, toread, ret);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        /* let's decrypt */
        /* we are reading buffers of crypto sector size (i.e. 4k, we must update IV each time */
        /* calculating current IV */
        if (fidostorate_get_iv_from_crypto_sector(curr_sector / 8, &ctx.key_h[0], &ctx.iv[0], 16)) {
            log_printf("[fidostorage] failed to initialize IV\n");
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
        }
        if (aes_init(&ctx.aes_ctx, ctx.key, AES256, &ctx.iv[0], CBC, AES_DECRYPT, AES_HARD_DMA, dma_in_complete, dma_out_complete, ctx.dma_in_desc, ctx.dma_out_desc) != 0) {
            log_printf("[fidostorage] failed while initialize AES\n");
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
        }

        random_secure = SEC_RANDOM_NONSECURE;
        if (aes_exec(&ctx.aes_ctx, ctx.buf, ctx.buf, ctx.buflen, ctx.dma_in_desc, ctx.dma_out_desc) != 0) {
            log_printf("[fidostorage] failed while execute AES decryption\n");
            random_secure = SEC_RANDOM_SECURE;
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
        }
        while (ctx.dma_out_finished == false) {
            ;
        }
        /* cryp DMA finished, clean flags */
        ctx.dma_out_finished = false;
        ctx.dma_in_finished = false;

        uint16_t numcell = ctx.buflen / sizeof(fidostorage_appid_table_t);
        fidostorage_appid_table_t   *appid_table = NULL;
        for (uint16_t j = 0; j < numcell; ++j) {
            appid_table = (fidostorage_appid_table_t*)&ctx.buf[(j*sizeof(fidostorage_appid_table_t))];
            // check if appid_matches
            if (memcmp(appid_table->appid, appid, 32) == 0) {
                log_printf("[fidostorage] found appid ! slot is %x\n", appid_table->slotid);
                /* appid matches ! return slot id and slot HMAC */
                *slot = appid_table->slotid;
                memcpy(hmac, &appid_table->hmac[0], 32);
                goto err;
            }
        }
        /* cells and sector have the same size */
        curr_sector += (ctx.buflen / sizeof(fidostorage_appid_table_t));
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
        loop_turn++;
#endif
    }
    /* appid not found !*/
    log_printf("[fidostorage] appid not found\n");
    errcode = MBED_ERROR_NOTFOUND;

err:
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    log_printf("[fidostorage] took %d ms to read, uncrypt and parse %d bytes from uSD\n", (uint32_t)(ms2-ms1), curr_sector*512);
    log_printf("[fidostorage] %d loops executed\n", loop_turn);
#endif
    random_secure = SEC_RANDOM_SECURE;
    return errcode;
}


mbed_error_t    fidostorage_register_appid(uint8_t const * const appid, uint32_t  * const appid_slot)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || appid_slot == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }


err:
    return errcode;
}

mbed_error_t    fidostorage_get_appid_metadata(uint8_t const * const     appid,
                                               uint32_t const            appid_slot,
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

    /* now, let's decrypt data that has been read */
    if (fidostorate_get_iv_from_crypto_sector(appid_slot / 8, &ctx.key_h[0], &ctx.iv[0], 16)) {
        log_printf("[fidostorage] failed to initialize IV\n");
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
    if (aes_init(&ctx.aes_ctx, ctx.key, AES256, &ctx.iv[0], CBC, AES_DECRYPT, AES_HARD_DMA, dma_in_complete, dma_out_complete, ctx.dma_in_desc, ctx.dma_out_desc) != 0) {
        log_printf("[fidostorage] failed while initialize AES\n");
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }

    /* we read potentially more than needed, but it is faster than reading two times, barsing icon len
     * after the first read. */
    uint16_t toread = SLOT_SIZE;

    /* here we have to cast uint8_t * to uint32_t * because sd_read reads words. Although
     * toread variable is calculated using the uint8_t* buf len. There is no overflow. */
    int ret;
    /* INFO: sd_read address argument is **sector address**. Sectors are 512 bytes len (same len as
     * fidostorage_appid_table_t cells).
     */
    if ((ret = sd_read((uint32_t*)data_buffer, appid_slot, toread)) != SD_SUCCESS) {
        log_printf("[fidostorage] Failed during SD_read, from sector %d, %d words to be read: ret=%d\n", appid_slot, toread, ret);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    /* let's decrypt first part of appid metadata (icon not included) */
    random_secure = SEC_RANDOM_NONSECURE;
    if (aes_exec(&ctx.aes_ctx, ctx.buf, (uint8_t*)data_buffer, toread, ctx.dma_in_desc, ctx.dma_out_desc) != 0) {
        log_printf("[fidostorage] failed while execute AES decryption\n");
        random_secure = SEC_RANDOM_SECURE;
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
    while (ctx.dma_out_finished == false) {
        ;
    }
    /* cryp DMA finished, clean flags */
    ctx.dma_out_finished = false;
    ctx.dma_in_finished = false;
    /* check if we need to read more (is there an icon to get back ? */
    fidostorage_appid_slot_t *mt = (fidostorage_appid_slot_t*)&data_buffer[0];

    /* is appid for this slot id match the one given ? */
    if (memcmp(appid, mt->appid, 32) != 0) {
        log_printf("[fidostorage] metadata does not correspond to the correct appid\n");
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
    uint32_t hmac_len = 0;


    hmac_init(&hmac_ctx, appid_slot_hmac, SHA256_DIGEST_SIZE, SHA256);
    hmac_update(&hmac_ctx, mt->appid, 32);
    hmac_update(&hmac_ctx, (uint8_t*)&mt->flags, 4);
    hmac_update(&hmac_ctx, mt->name, 60);
    hmac_update(&hmac_ctx, (uint8_t*)&mt->ctr, 4);
    hmac_update(&hmac_ctx, (uint8_t*)&mt->icon_len, 2);
    hmac_update(&hmac_ctx, (uint8_t*)&mt->icon_type, 2);
    if (mt->icon_len != 0) {
        hmac_update(&hmac_ctx, &mt->icon.icon_data[0], mt->icon_len);
    }
    hmac_finalize(&hmac_ctx, &hmac[0], &hmac_len);
    if (memcmp(hmac, appid_slot_hmac, 32) != 0) {
        log_printf("[fidostorage] metadata HMAC does not match given one !!!\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    log_printf("[fidostorage] appid metadata valid !\n");
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

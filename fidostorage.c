#include "libc/types.h"
#include "libc/random.h"
#include "libc/string.h"
#include "libc/stdio.h"
#include "libc/sync.h"
#include "libc/random.h"
#include "aes.h"
#include "libsd.h"
#include "api/libfidostorage.h"


#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

#define SECTOR_SIZE 512





typedef struct {
    uint8_t     *buf;
    uint16_t     buflen;
    uint8_t      iv[16]; /* do we consider CTR with incremental iv=0 for slot=0 ? */
    uint8_t      key[16];
    aes_context  aes_ctx; /* aes context */
    bool         configured;
} fidostorage_ctx_t;


typedef enum {
    SLOTID_FREE     = 0x15e4f8a6UL,
    SLOTID_USED     = 0x7f180654UL
} fidostorage_appid_table_flag_t;

typedef struct __packed {
    uint32_t    flag;
    uint8_t     appid[32];
    uint32_t    slotid;
    // hmac ? other ?
    uint8_t     reserved[24]; /* padding to SD sector size */
} fidostorage_appid_table_t;

static fidostorage_ctx_t ctx = { 0 };

/**********************************************************
 * local utility functions
 */

static inline bool fidostorage_is_configured(void) {
    return (ctx.configured == true);
}


/**********************************************************
 * init, configure library
 */

/*@
  @ requires \separated(black_buf + (0 .. buflen-1),red_buf + (0 .. buflen-1),&ctx);
 */
mbed_error_t    fidostorage_configure(uint8_t *buf, uint16_t  buflen)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* we wish to read from the appid table list at least 4 appid slot identifier at a time,
     * for performance constraints */
    uint16_t minsize = 4*sizeof (fidostorage_appid_table_t);

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
    ctx.configured = true;
    request_data_membarrier();
err:
    return errcode;
}

/**********************************************************
 * Manipulate storage content
 */

/* appid is 32 bytes len identifier */
mbed_error_t    fidostorage_get_appid_slot(uint8_t* appid, uint32_t *slot)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* get back buflen (in bytes), convert to words. buflen is already word multiple */
    uint32_t toread = ctx.buflen / 4;
    uint32_t curr_sector = 0;



    if (!fidostorage_is_configured()) {
        log_printf("[fidostorage] not yet configured!\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || slot == NULL) {
        log_printf("[fidostorage] invalid param !\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);

    /* now, let's decrypt data that has been read */
    if (aes_init(&ctx.aes_ctx, ctx.key, AES128, ctx.iv, CTR, AES_DECRYPT, AES_SOFT_UNMASKED, NULL, NULL, -1, -1) != 0) {
        log_printf("[fidostorage] failed while initialize AES\n");
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }


    while (curr_sector < (MAX_APPID_TABLE_LEN / SECTOR_SIZE)) {
        /* here we have to cast uint8_t * to uint32_t * because sd_read reads words. Although
         * toread variable is calculated using the uint8_t* buf len. There is no overflow. */
        //log_printf("[fidostorage] reading %d bytes starting from sector %x (@[bytes]: \n", ctx.buflen, curr_sector, curr_sector*SECTOR_SIZE);
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
#if 1
        random_secure = SEC_RANDOM_NONSECURE;
        if (aes_exec(&ctx.aes_ctx, ctx.buf, ctx.buf, ctx.buflen, -1, -1) != 0) {
            log_printf("[fidostorage] failed while execute AES decryption\n");
            random_secure = SEC_RANDOM_SECURE;
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
        }
#endif

        // FIX here we call aes on black buf, decrypt toward red_buf

        /* decrypted data are in red_buf, we can read from it... */
        uint16_t numcell = ctx.buflen / sizeof(fidostorage_appid_table_t);
        fidostorage_appid_table_t   *appid_table = NULL;
        for (uint16_t i = 0; i < numcell; ++i) {
            appid_table = (fidostorage_appid_table_t*)&ctx.buf[(i*sizeof(fidostorage_appid_table_t))];
            // check if appid_matches
            if (memcmp(appid_table->appid, appid, 32) == 0) {
                log_printf("[fidostorage] found appid ! slot is %x\n", appid_table->slotid);
                /* appid matches ! */
                *slot = appid_table->slotid;
                goto err;
            }
        }
        /* cells and sector have the same size */
        curr_sector += numcell;
    }
    /* appid not found !*/
    log_printf("[fidostorage] appid not found\n");
    errcode = MBED_ERROR_NOTFOUND;

err:
    sys_get_systick(&ms2, PREC_MILLI);
    log_printf("[fidostorage] took %d ms to read, uncrypt and parse %d bytes from uSD\n", (uint32_t)(ms2-ms1), curr_sector*512);
    random_secure = SEC_RANDOM_SECURE;
    return errcode;
}


mbed_error_t    fidostorage_set_appid_slot(uint8_t*appid, uint32_t  *slotid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint32_t toread = ctx.buflen / 4;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || slotid == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    uint32_t curr_sector = 0;

    while (curr_sector < (MAX_APPID_TABLE_LEN / SECTOR_SIZE)) {
        /* here we have to cast uint8_t * to uint32_t * because sd_read reads words. Although
         * toread variable is calculated using the uint8_t* buf len. There is no overflow. */
        log_printf("[fidostorage] reading %d bytes starting from sector %x (@[bytes]: \n", ctx.buflen, curr_sector, curr_sector*SECTOR_SIZE);
        int ret;
        /* INFO: sd_read address argument is **sector address**. Sectors are 512 bytes len (same len as
         * fidostorage_appid_table_t cells).
         */
        if ((ret = sd_read((uint32_t*)&ctx.buf[0], curr_sector, toread)) != SD_SUCCESS) {
            log_printf("[fidostorage] Failed during SD_read, from sector %d, %d words to be read: ret=%d\n", curr_sector, toread, ret);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        /* now, let's decrypt data that has been read */

        // FIX here we call aes on black buf, decrypt toward red_buf

        /* decrypted data are in red_buf, we can read from it... */
        uint16_t numcell = ctx.buflen / sizeof(fidostorage_appid_table_t);
        fidostorage_appid_table_t   *appid_table = NULL;
        for (uint16_t i = 0; i < numcell; ++i) {
            appid_table = (fidostorage_appid_table_t*)&ctx.buf[(i*sizeof(fidostorage_appid_table_t))];
            if (appid_table->flag != SLOTID_USED) {
                /* this slot is free, we can use it */
                /*
                 * we can write back appid ref to current cell in SD.
                 * the associated slotid is the one already set in SDCard, as this one is free.
                 * The corresponding metadata will have to be set using fidostorage_set_appid_metadata()
                 * using the slotid we update here
                 */
                *slotid = appid_table->slotid;
            }
        }
        /* cells and sector have the same size */
        curr_sector += numcell;
    }
    /* appid not found !*/
    log_printf("[fidostorage] appid not found\n");
    errcode = MBED_ERROR_NOMEM;

err:
    return errcode;
}

mbed_error_t    fidostorage_get_appid_metadata(uint8_t const * const appid, uint32_t    appid_slot, uint8_t *data_buffer)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || data_buffer == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    // TODO
    appid_slot = appid_slot;


err:
    return errcode;
}

mbed_error_t    fidostorage_set_appid_metada(uint8_t *appid, uint32_t   appid_slot, fidostorage_appid_metadata_t const * const metadata)
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
    appid_slot = appid_slot;

err:
    return errcode;
}

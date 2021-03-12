#include "libc/types.h"
#include "libc/random.h"
#include "libc/string.h"
#include "libc/sync.h"
#include "aes.h"
#include "libsd.h"
#include "api/libfidostorage.h"


#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

typedef struct {
    uint8_t     *black_buf;
    uint8_t     *red_buf;
    uint16_t     buflen;
    uint8_t      key[256];
    bool         configured;
} fidostorage_ctx_t;


typedef struct __packed {
    // hmac ? other ?
    uint8_t     appid[32];
    uint32_t    slotid;
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
mbed_error_t    fidostorage_configure(uint8_t *black_buf, uint8_t *red_buf, uint16_t  buflen)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* we wish to read from the appid table list at least 4 appid slot identifier at a time,
     * for performance constraints */
    uint16_t minsize = 4*sizeof (fidostorage_appid_table_t);

    if (black_buf == NULL || red_buf == NULL || buflen == 0) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (buflen < minsize) {
        log_printf("buffer too small, should be at least %d bytes len\n", minsize);
        errcode = MBED_ERROR_NOMEM;
        goto err;
    }
    ctx.red_buf = red_buf;
    ctx.black_buf = black_buf;
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



    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL || slot == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    uint32_t address = 0x0;

    while (address != (MAX_APPID_TABLE_LEN - ctx.buflen)) {
        /* here we have to cast uint8_t * to uint32_t * because sd_read reads words. Although
         * toread variable is calculated using the uint8_t* buf len. There is no overflow. */
        if (sd_read((uint32_t*)&ctx.black_buf[0], address, toread) != 0) {
            log_printf("[fidostorage] Failed during SD_read, sector 0x0, %d words to be read\n", toread);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        /* now, let's decrypt data that has been read */

        // FIX here we call aes on black buf, decrypt toward red_buf

        /* decrypted data are in red_buf, we can read from it... */
        fidostorage_appid_table_t   *appid_table = NULL;
        uint16_t numcell = ctx.buflen / sizeof(fidostorage_appid_table_t);
        for (uint16_t i = 0; i < numcell; ++i) {
            appid_table = (fidostorage_appid_table_t*)&ctx.red_buf[(i*sizeof(fidostorage_appid_table_t))];
            // check if appid_matches
            if (memcmp(appid_table->appid, appid, 32) == 0) {
                /* appid matches ! */
                *slot = appid_table->slotid;
                goto err;
            }
        }
        address += ctx.buflen;
    }
    /* appid not found !*/
    errcode = MBED_ERROR_NOTFOUND;

err:
    return errcode;
}


mbed_error_t    fidostorage_set_appid_slot(uint8_t*appid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

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

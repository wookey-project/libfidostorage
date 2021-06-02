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
    uint8_t     kh[32];                     /*< application ley handle hash */
    uint32_t    slotid;                     /*< slot identifier, corresponding to sector identifier in SDCard
                                                where the appid infos are written */
    uint8_t     hmac[32];                   /*< appid slot HMAC        */
    uint8_t     padding[SECTOR_SIZE - 68 - 32];  /*< padding to sector size */
} fidostorage_appid_table_t;

#define SLOT_ENTRY_TO_HMAC_SIZE(x) (sizeof(fidostorage_appid_table_t) - sizeof((x).padding))

/*
 * Specify the effective SDCard header structure (size 4096 bytes).
 * This structure simplify the access to the first crypto sector.
 * The appid_table is not mapped in the structure (0-sized) but yet declared.
 */
typedef struct __packed {
    uint8_t     bitmap[SLOT_NUM / 8];                   /*< list of activated/unactivated slots (bitmap): size: 1k (2 sectors) */
    uint64_t    ctr_replay;                             /* < anti-replay counter */
    uint8_t     hmac[32];                               /*< HMAC for the overall fifodstorage_header_t */
    uint8_t     hmac_padding[SECTOR_SIZE - 32 - 8];         /*< HMAC padding with zeros */
    uint8_t     crypto_sector_padding[5*SECTOR_SIZE];   /*< padding to align appid_table to 4k */
    fidostorage_appid_table_t   appid_table[0];         /*< table of all appid header (se above) */
} fidostorage_header_t;

static fidostorage_ctx_t ctx = { 0 };



/**********************************************************
 * local utility functions
 */

static inline bool slotnum_to_slotid(uint32_t num, uint32_t *slotid)
{
    if((num >= SLOT_NUM) || (slotid == NULL)){
        return false;
    }
    *slotid = (((SLOT_NUM / 8) + 1 + num) * SLOT_SIZE) / SECTOR_SIZE;
    return true;
}

static inline bool slotid_to_slotnum(uint32_t slotid, uint32_t *num)
{
    if(slotid <= ((((SLOT_NUM / 8) + 1) * SLOT_SIZE) / SECTOR_SIZE)){
        return false;
    }
    if(num == NULL){
        return false;
    }
    *num =  ((slotid * SECTOR_SIZE) - (((SLOT_NUM / 8) + 1) * SLOT_SIZE)) / SLOT_SIZE;
    return true;
}

static inline bool is_slot_active(uint32_t num, const uint8_t *bitmap)
{
    if((num > SLOT_NUM) || (bitmap == NULL)){
        return false;
    }
    if(bitmap[num / 8] & (0x1 << (num % 8))){
        return true;
    }
    return false;
}

static inline void set_slot_active(uint32_t num, uint8_t *bitmap)
{
    if((num > SLOT_NUM) || (bitmap == NULL)){
        return;
    }
    bitmap[num / 8] |= (0x1 << (num % 8));
    return;
}

static inline void set_slot_inactive(uint32_t num, uint8_t *bitmap)
{
    if((num > SLOT_NUM) || (bitmap == NULL)){
        return;
    }
    if(bitmap[num / 8] & (0x1 << (num % 8))){
        bitmap[num / 8] ^= (0x1 << (num % 8));
    }
    return;
}


/* Find a free slot */
static bool find_free_slot(uint32_t *num, uint32_t *slotid, const uint8_t *bitmap)
{
    if((num == NULL) || (slotid == NULL) || (bitmap == NULL)){
        return false;
    }
    /* Search for a free slot in our bitmap */
    unsigned int i;
    for(i = 0; i < SLOT_NUM; i++){
        if(!is_slot_active(i, bitmap)){
            *num = i;
            if(!slotnum_to_slotid(i, slotid)){
                return false;
            }
            return true;
        }
    }
    return false;
}

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

#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
    printf("HMAC key is: ");
    hexdump(key_h, 32);
#endif
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

#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
    log_printf("AES key is: ");
    hexdump(key_aes, 32);
#endif
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

/* Shadow bitmap for caching */
static uint8_t shadow_bitmap[1024 + 8 + 32] = { 0 };

/**********************************************************
 * Manipulate storage content
 */

/* Find a free slot and return its slot number and slotid */
bool fidostorage_find_free_slot(uint32_t *num, uint32_t *slotid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* First of all, read the bitmap */
    if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] failed while reading bitmap and HMAC\n");
        goto err;
    }
    fidostorage_header_t *header = (fidostorage_header_t*)&ctx.buf[0];

    /* Copy our shadow bitmap table */
    memcpy(shadow_bitmap, &(header->bitmap), sizeof(shadow_bitmap));

    return find_free_slot(num, slotid, shadow_bitmap);
err:
    return false;
}

/* appid is 32 bytes len identifier */
mbed_error_t    fidostorage_get_appid_slot(uint8_t const appid[32], uint8_t const kh[32], uint32_t *slotid, uint8_t hmac[32], uint8_t replay_counter[8], bool check_header)
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
    uint16_t active_slots = 0;

    if (!fidostorage_is_configured()) {
        log_printf("[fidostorage] not yet configured!\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (appid != NULL){
        if (slotid == NULL || hmac == NULL) {
            log_printf("[fidostorage] invalid param !\n");
            errcode = MBED_ERROR_INVPARAM;
            goto err;
        }
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);
#endif

    if (check_header != false) {
        /* initialize HMAC calculation */
        hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);
    }

    /* we start from sector 0, to get back the bitmap and the HMAC */
    if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] failed while reading bitmap and HMAC\n");
        goto err;
    }
    /* get back HMAC */
    fidostorage_header_t *header = (fidostorage_header_t*)&ctx.buf[0];

    if (check_header != false) {
        memcpy(header_hmac, &header->hmac[0], 32);
    }

    if (check_header != false) {
        /* starting HMAC calculation */
        hmac_update(&hmac_ctx, header->bitmap, sizeof(header->bitmap));
        hmac_update(&hmac_ctx, (uint8_t*)&(header->ctr_replay), sizeof(header->ctr_replay));
    }
    if(replay_counter != NULL){
        if(sizeof(header->ctr_replay) != 8){
            errcode = MBED_ERROR_INVPARAM;
            goto err;
        }
        memcpy(replay_counter, (uint8_t*)&(header->ctr_replay), 8);
    }

    /* Copy our shadow bitmap table */
    memcpy(shadow_bitmap, &(header->bitmap), sizeof(shadow_bitmap));

    /* now reading the effective slot sectors */
    curr_sector++;
    bool slot_found = false;
    /* looping on slotting table, reading 8 cells each time */
    while (curr_sector <= (SLOT_NUM/8)) {
        //log_printf("[fidostorage] reading %d bytes starting from (crypto) sector %x (@[bytes]: %d\n", ctx.buflen, curr_sector, curr_sector*SLOT_SIZE);
        /* INFO: sd_read address argument is **sector address**. Sectors are 512 bytes len (same len as
         * fidostorage_appid_table_t cells).
         */
        /* Only consider active slots, skip the inactive ones */
        if(shadow_bitmap[curr_sector-1] == 0){
            goto next;
        }
        if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, curr_sector)) != MBED_ERROR_NONE) {
            log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", curr_sector, errcode);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        uint16_t numcell = 8; /* there are 8 cells per 4k read (512 bytes per cell) */
        fidostorage_appid_table_t   *appid_table = (fidostorage_appid_table_t*)&ctx.buf[0];
        for (uint16_t j = 0; j < numcell; j++) {
            if (shadow_bitmap[curr_sector-1] & (0x1 << j)){
                active_slots++;
                /* does current cell appid matches ? */
                if ((appid != NULL) && (memcmp(appid_table[j].appid, appid, 32) == 0)) {
                    if(kh != NULL){
                        /* Check the key handle hash if asked to */
                        if (memcmp(appid_table[j].kh, kh, 32) != 0) {
                            goto skip;
                        }
                    }
                    log_printf("[fidostorage] found appid! slot id is 0x%x\n", appid_table[j].slotid);
                    /* appid matches ! return slot id and slot HMAC */
                    *slotid = appid_table[j].slotid;
                    memcpy(hmac, &appid_table[j].hmac, sizeof(appid_table[j].hmac));
                    slot_found = true;
                    if (check_header == false) {
                        /* no header HMAC calculation, we can leave now */
                        break;
                    }
                }
skip:
                if (check_header != false) {
                    /* update calculated HMAC */
                    hmac_update(&hmac_ctx, &appid_table[j].appid[0], SLOT_ENTRY_TO_HMAC_SIZE(appid_table[j]));
                }
            }
        }
next:
        curr_sector++;
    }
    if (check_header != false) {
        hmac_finalize(&hmac_ctx, &calculated_hmac[0], &hmac_len);

#if CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
        log_printf("Header HMAC read on SD:\n");
        hexdump(header_hmac, 32);
        log_printf("Header calculated HMAC:\n");
        hexdump(calculated_hmac, hmac_len);
#endif
        if (memcmp(&header_hmac[0], &calculated_hmac[0], hmac_len) != 0) {
            log_printf("[logstorage] slot table integrity check failed !\n");
        }
    }
    if ((appid != NULL) && (slot_found != true)) {
        /* appid not found !*/
        log_printf("[fidostorage] appid not found\n");
        errcode = MBED_ERROR_NOTFOUND;
    }
err:
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    printf("[fidostorage] took %d ms to get appid slot from encrypted header (%d bytes read from uSD)\n", (uint32_t)(ms2-ms1), active_slots*SECTOR_SIZE);
    printf("[fidostorage] %d loops executed, %d active slots\n", (curr_sector-1), active_slots);
#endif
    return errcode;
}


mbed_error_t    fidostorage_get_appid_metadata(const uint8_t appid[32],
                                               const uint8_t kh[32],
                                               const uint32_t slotid,
                                               const uint8_t appid_slot_hmac[32],
                                               fidostorage_appid_slot_t *data_buffer)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    fidostorage_appid_slot_t *mt  = NULL;

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

    if ((errcode = read_encrypted_SD_crypto_sectors((uint8_t*)data_buffer, SLOT_SIZE, (SECTOR_SIZE * slotid) / SLOT_SIZE)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", (SECTOR_SIZE * slotid) / SLOT_SIZE, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    mt = (fidostorage_appid_slot_t*)&data_buffer[0];

    /* is appid for this slot id match the one given ? */
    if (memcmp(appid, mt->appid, 32) != 0) {
        log_printf("[fidostorage] metadata of slotid = 0x%x does not correspond to the correct appid\n", slotid);
#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
        hexdump(appid, 32);
        hexdump(mt->appid, 32);
#endif
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if ((kh != NULL) && (memcmp(kh, mt->kh, 32) != 0)) {
        log_printf("[fidostorage] metadata of slotid = 0x%x does not correspond to the correct kh\n", slotid);
#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
        hexdump(kh, 32);
        hexdump(mt->kh, 32);
#endif
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    /* overflow detection */
    if (mt->icon_type == ICON_TYPE_IMAGE &&
        mt->icon_len > (SLOT_SIZE - (sizeof(fidostorage_appid_slot_t) - sizeof(fidostorage_icon_data_t)))) {
        log_printf("[fidostorage] metadata icon len (%d) is invalid (too big)\n", mt->icon_len);
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    else if (mt->icon_type == ICON_TYPE_COLOR &&
        mt->icon_len != 3) {
        log_printf("[fidostorage] metadata icon len for color is invalid (too big)\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    else if (mt->icon_type == ICON_TYPE_NONE &&
             mt->icon_len != 0) {
        log_printf("[fidostorage] metadata icon len for none is invalid (too big)\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    /* check slot integrity */
    hmac_context hmac_ctx;
    uint8_t         hmac[32];
    uint32_t hmac_len = sizeof(hmac);


    hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);
    hmac_update(&hmac_ctx, (uint8_t*)mt, SLOT_MT_SIZE);
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
err:
    if (mt) {
    fidostorage_dump_slot(mt);
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    printf("[fidostorage] took %d ms to get appid metadata from encrypted slot in uSD\n", (uint32_t)(ms2-ms1));
#endif
    random_secure = SEC_RANDOM_SECURE;
    return errcode;
}

mbed_error_t    fidostorage_set_appid_metadata(uint32_t  *slotid, fidostorage_appid_slot_t const * const metadata)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    printf("%s: dumping metadata that will be set...\n", __func__);
    fidostorage_dump_slot(metadata);

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (slotid == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if((*slotid == 0) && (metadata == NULL)){
        /* We cannot ask to remove a non existing slot ... */
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);
#endif

    /* Let us compute the HMAC of our metadata */
    uint8_t         hmac_slot[32];
    hmac_context hmac_ctx;
    uint32_t hmac_len = 0;

    if(metadata != NULL){
        hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);
        hmac_update(&hmac_ctx, (uint8_t*)metadata, SLOT_MT_SIZE);
        if (metadata->icon_len != 0) {
            hmac_update(&hmac_ctx, &metadata->icon.icon_data[0], metadata->icon_len);
        }
        hmac_len = sizeof(hmac_slot);
         hmac_finalize(&hmac_ctx, &hmac_slot[0], &hmac_len);
#if CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
        log_printf("Calculated HMAC of slot:\n");
        hexdump(hmac_slot, hmac_len);
#endif
    }
    /* First, read our first header sector */
    if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], SLOT_SIZE, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", 0, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    /* Copy our shadow bitmap */
    memcpy(shadow_bitmap, &ctx.buf[0], sizeof(shadow_bitmap));

    uint32_t curr_slotid;
    uint32_t curr_slotnum;
    /* Are we asked to allocate a new slotid? */
    if(*slotid == 0){
        /* Find the first slot */
        if(!find_free_slot(&curr_slotnum, &curr_slotid, shadow_bitmap)){
  	    errcode = MBED_ERROR_NOMEM;
            goto err;
        }
        *slotid = curr_slotid;
    }
    else{
        /* Use the provided slotid with sanity check */
        if(!slotid_to_slotnum(*slotid, &curr_slotnum)){
  	    errcode = MBED_ERROR_INVPARAM;
            goto err;
	}
        curr_slotid = *slotid;
    }
    /* We have found our slot, now go on with the modifications */
    if(metadata == NULL){
        /* We are asked to remove the slot */
        set_slot_inactive(curr_slotnum, shadow_bitmap);
    }
    else{
        /* Activate the slot in the shadow bitmap */
        set_slot_active(curr_slotnum, shadow_bitmap);
    }

    /* Write the slot content */
    /* TODO: better size handling */
    memset(&ctx.buf[0], 0, ctx.buflen); /* Write zeros to the slot is asked to remove */
    if(metadata != NULL){
        if(SLOT_MT_SIZE > ctx.buflen){
      	    errcode = MBED_ERROR_INVPARAM;
            goto err;
        }
        memcpy(&ctx.buf[0], metadata, SLOT_MT_SIZE);
        if (metadata->icon_len != 0) {
            if((SLOT_MT_SIZE + metadata->icon_len) > ctx.buflen){
      	        errcode = MBED_ERROR_INVPARAM;
                goto err;
            }
            memcpy(&ctx.buf[0] + SLOT_MT_SIZE, &metadata->icon.icon_data[0], metadata->icon_len);
        }
    }

    printf("[XXX] writing buffer to SD\n");
    printf("[XXX] buff appid is:\n");
    hexdump((fidostorage_appid_slot_t*)(&ctx.buf[0]).appid, 32);
    printf("[XXX] buffKH is:\n");
    hexdump((fidostorage_appid_slot_t*)(&ctx.buf[0]).kh, 32);
    if ((errcode = write_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, (SECTOR_SIZE * curr_slotid) / SLOT_SIZE)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_write, from sector %d: ret=%d\n", (SECTOR_SIZE * curr_slotid) / SLOT_SIZE, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }

    /* Compute our new header HMAC */
    hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);
    hmac_update(&hmac_ctx, shadow_bitmap, 1024 + 8);

    unsigned int i;
    for(i = 0; i < (SLOT_NUM / 8); i++){
        /* Skip inactive slots */
        if(shadow_bitmap[i] == 0){
            continue;
        }
        /* Read our slot entry */
        if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, (i+1))) != MBED_ERROR_NONE) {
            log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", i, errcode);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        uint16_t numcell = 8; /* there are 8 cells per 4k read (512 bytes per cell) */

        fidostorage_appid_table_t   *appid_table = (fidostorage_appid_table_t*)&ctx.buf[0];
        bool to_write = false;
        for (uint16_t j = 0; j < numcell; j++) {
            if (shadow_bitmap[i] & (0x1 << j)){
                if (curr_slotnum == ((8*i) + j)) {
                    /* Replace data */
                    memcpy(&appid_table[j].appid[0], metadata->appid, 32);
                    memcpy(&appid_table[j].kh[0], metadata->kh, 32);
                    appid_table[j].slotid = curr_slotid;
                    memcpy(&appid_table[j].hmac, hmac_slot, sizeof(hmac_slot));
                    to_write = true;
                }
                /* update calculated HMAC */
                hmac_update(&hmac_ctx, &appid_table[j].appid[0], SLOT_ENTRY_TO_HMAC_SIZE(appid_table[j]));
            }
        }
        if(to_write == true){
            /* Write back our modified slot entry if necessary */
            if ((errcode = write_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, (i+1))) != MBED_ERROR_NONE) {
                log_printf("[fidostorage] Failed during SD_enc_write, from sector %d: ret=%d\n", i, errcode);
                errcode = MBED_ERROR_RDERROR;
                goto err;
            }
        }
    }
    /* Finalize HMAC computation */
    hmac_len = 32;
    hmac_finalize(&hmac_ctx, shadow_bitmap + 1024 + 8, &hmac_len);
    memset(&ctx.buf[0], 0, ctx.buflen);
    memcpy(&ctx.buf[0], shadow_bitmap, sizeof(shadow_bitmap));
    /* Now commit the shadow map and its hmac */
    if ((errcode = write_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_write, from sector %d: ret=%d\n", 0, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    printf("[fidostorage] took %d ms to update encrypted appid metadata in uSD\n", (uint32_t)(ms2-ms1));
#endif


err:
    return errcode;
}


mbed_error_t    fidostorage_get_replay_counter(uint8_t replay_counter[8], bool check_header)
{
    return fidostorage_get_appid_slot(NULL, NULL, NULL, NULL, replay_counter, check_header);
}


mbed_error_t    fidostorage_set_replay_counter(const uint8_t replay_counter[8])
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    hmac_context hmac_ctx;
    uint32_t hmac_len = 0;

    if (!fidostorage_is_configured()) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    uint64_t ms1, ms2;

    sys_get_systick(&ms1, PREC_MILLI);
#endif
    /* First, read our first header sector */
    if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], SLOT_SIZE, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", 0, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    /* Copy our shadow bitmap */
    memcpy(shadow_bitmap, &ctx.buf[0], sizeof(shadow_bitmap));

    /* Update the global anti-replay counter with the provided value */
    memcpy(&shadow_bitmap[1024], replay_counter, 8);

    /* Compute our new header HMAC */
    hmac_init(&hmac_ctx, &ctx.hmac_key[0], sizeof(ctx.hmac_key), SHA256);
    hmac_update(&hmac_ctx, shadow_bitmap, 1024 + 8);

    unsigned int i;
    for(i = 0; i < (SLOT_NUM / 8); i++){
        /* Skip inactive slots */
        if(shadow_bitmap[i] == 0){
            continue;
        }
        /* Read our slot entry */
        if ((errcode = read_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, (i+1))) != MBED_ERROR_NONE) {
            log_printf("[fidostorage] Failed during SD_enc_read, from sector %d: ret=%d\n", i, errcode);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        uint16_t numcell = 8; /* there are 8 cells per 4k read (512 bytes per cell) */

        fidostorage_appid_table_t   *appid_table = (fidostorage_appid_table_t*)&ctx.buf[0];
        for (uint16_t j = 0; j < numcell; j++) {
            if (shadow_bitmap[i] & (0x1 << j)){
                /* update calculated HMAC */
                hmac_update(&hmac_ctx, &appid_table[j].appid[0], SLOT_ENTRY_TO_HMAC_SIZE(appid_table[j]));
            }
        }
    }
    /* Finalize HMAC computation */
    hmac_len = 32;
    hmac_finalize(&hmac_ctx, shadow_bitmap + 1024 + 8, &hmac_len);
    memset(&ctx.buf[0], 0, ctx.buflen);
    memcpy(&ctx.buf[0], shadow_bitmap, sizeof(shadow_bitmap));
    /* Now commit the shadow map and its hmac */
    if ((errcode = write_encrypted_SD_crypto_sectors(&ctx.buf[0], ctx.buflen, 0)) != MBED_ERROR_NONE) {
        log_printf("[fidostorage] Failed during SD_enc_write, from sector %d: ret=%d\n", 0, errcode);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
#if CONFIG_USR_LIB_FIDOSTORAGE_PERFS
    sys_get_systick(&ms2, PREC_MILLI);
    printf("[fidostorage] took %d ms to update global anti-replay counter\n", (uint32_t)(ms2-ms1));
#endif


err:
    return errcode;
}

mbed_error_t    fidostorage_inc_replay_counter(const uint8_t replay_counter[8])
{
    /* Increment little endian counter */
    uint64_t *ctr = (uint64_t*)replay_counter;
    (*ctr)++;

    return MBED_ERROR_NONE;
}

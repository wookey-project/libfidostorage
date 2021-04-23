/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
#ifndef LIBFIDOSTORAGE_H_
#define LIBFIDOSTORAGE_H_

/*
 * How it works:
 *
 *
 *        SDCard (encrypted)
 * | bitmap of active sectors   | (len 1024 (two sectors))
 * |----------------------------|
 * | hmac of slotting table     | (len 512)
 * |######## (padding) ######## | (len 512+2048)
 * |----------------------------|               \
 * | appid1|slotid1|hmac        | (len 512)     |
 * |----------------------------|               |
 * | appid2|slotid2|hmac        | (len 512)     = global slotting table
 * |----------------------------|               |
 * | appid3|slotid3|hmac        | (len 512)     |
 * |----------------------------|               /
 * | ... (upto 4M len max)      |
 * |                            |
 * |xxxxxxxxx (padding) xxxxxxxx|
 * |----------------------------|
 * |appid|ctr|icon-type|icon_len|
 * |icon.........               |
 * |              xxx(padding)xx|
 * |----------------------------|
 * |appid|ctr|icon-type|icon_len|
 * |icon.........               |
 * |----------------------------|
 *
 *
 * We first read the global slotting table to get back the
 * metadata sector addr (slotid) associated to the corresponding
 * appid.
 * We then get back the metadata of this appid and use it.
 *
 * By default, all well-known appid (google, gitlab, etc.)
 * have their {appid/slotid} couple set and metadata icon
 * set. The flag is marked as free while no register has
 * been executed.
 *
 * This allows to use predefined icons for these well-known appid.
 *
 * This library also provides setting API to set metadata and
 * register a new appid to the first free line of the slotting
 * table.
 */

/* standard SD Card sector size */
#define SECTOR_SIZE 512

#define SLOT_SIZE 4096

/* 8192 slots max */
#define SLOT_NUM 8192



typedef enum {
    ICON_TYPE_IMAGE = 0,
    ICON_TYPE_COLOR = 1,
    ICON_TYPE_NONE = 2
} fidostorage_icon_type_t;

/*
 * An icon is one of the following (depending on icon type): RGB color, or effective icon
 */
typedef union {
    uint8_t                 rgb_color[3];
    uint8_t                 icon_data[0];
} fidostorage_icon_data_t;

/*
 * The effective appid information structure
 */
typedef struct __packed  __attribute__ ((aligned (4))) {
    uint8_t     appid[32];              /*< application identifier */
    uint32_t    flags;                  /*< various U2F2 specific flags */
    uint8_t     name[60];               /*< Appid human readable name */
    uint32_t    ctr;                    /*< CTR value */
    uint16_t    icon_len;               /*< icon length in bytes (for icon data type */
    uint16_t    icon_type;              /*< icon type (RGB color or icon data) */
    fidostorage_icon_data_t icon;       /*< icon data union (RGB color value or icon data value in RLE encoding) */
} fidostorage_appid_slot_t;


/* declaration phase */
mbed_error_t fidostorage_declare(void);

/* configure buffers */
mbed_error_t    fidostorage_configure(uint8_t *buf, uint16_t  buflen, uint8_t *aes_key);

/* given an appid, is the appid valid (already at least registered) ? - bitmap check */
mbed_error_t    fidostorage_appid_is_valid(uint8_t *appid);

mbed_error_t    fidostorage_check_appid_table_integrity(void);

/**
 * get the appid storage slot from the appid value
 * @param appid  the effective FIDO appid value
 * @param slot   the slotid to return
 * @param hmac   the slot HMAC to return
 *
 * @return MBED_ERROR_NONE if the appid is found, or MBED_ERROR_NOTFOUND if not.
 */
mbed_error_t    fidostorage_get_appid_slot(uint8_t const * const appid, uint32_t * const slot, uint8_t * const hmac);

/**
 * get the appid slot content from the appid value, its slot id and HMAC value. The slot
 * integrity is checked by this function.
 * @param appid           the effective FIDO appid value
 * @param appid_slot      the appid slot identifier returned by fidostorage_get_appid_slot
 * @param appid_slot_hmac the appid slot HMAC returned by fidostorage_get_appid_slot
 * @param data_buffer     the effective appid metainformations to return
 *
 * @return MBED_ERROR_NONE if the appid is found, or MBED_ERROR_NOTFOUND if not.
 */
mbed_error_t    fidostorage_get_appid_metadata(uint8_t const * const     appid,
                                               uint32_t const            appid_slot,
                                               uint8_t const *           appid_slot_hmac,
                                               fidostorage_appid_slot_t *data_buffer);


mbed_error_t    fidostorage_register_appid(uint8_t const * const appid, uint32_t  * const appid_slot);

mbed_error_t    fidostorage_set_appid_metada(uint8_t *appid, uint32_t   appid_slot, fidostorage_appid_slot_t const * const metadata);

#endif/*!LIBFIDOSTORAGE_H_*/

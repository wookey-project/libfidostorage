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
 *      SDCard (encrypted)
 *
 * |----------------------------|               \
 * | flag|appid1|slotid1|xxxxxxx| (len 512)     |
 * |----------------------------|               |
 * | flag|appid2|slotid2|xxxxxxx| (len 512)     = global slotting table
 * |----------------------------|               |
 * | flag|appid3|slotid3|xxxxxxx| (len 512)     |
 * |----------------------------|               /
 * | ... (upto 4M len max)      |
 * |                            |
 * |xxxxxxxxx (padding) xxxxxxxx|
 * |----------------------------|
 * |           hmac             | <---- at slotid1 sector @
 * |appid|ctr|icon-type|icon_len|
 * |icon.........               |
 * |              xxx(padding)xx|
 * |----------------------------|
 * |           hmac             | <---- at slotid2 sector @
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

#define MAX_APPID_TABLE_LEN 4000000UL /* 4MB */

typedef enum {
    ICON_TYPE_IMAGE = 0,
    ICON_TYPE_COLOR = 1,
} fidostorage_icon_type_t;

typedef union {
    uint8_t rgb_color[3];
    uint8_t icon[0]; /* null-sized */
} fidostorage_icon_data_t;

typedef struct __packed {
    uint8_t      hmac[64];
    uint8_t      appid[32];
    uint32_t     ctr;
    uint8_t      icon_type;
    uint16_t     icon_len;
    /* when setting new apid, there is no need to specify the icon content in case of icon image,
     * as the icon image is already set in the SDCard. In case of icon color, use the
     * rgb field of the union. */
    fidostorage_icon_data_t  icon;
} fidostorage_appid_metadata_t;


mbed_error_t    fidostorage_configure(uint8_t *buf, uint16_t  buflen);

mbed_error_t    fidostorage_get_appid_slot(uint8_t* appid, uint32_t *slot);

mbed_error_t    fidostorage_set_appid_slot(uint8_t*appid, uint32_t  *slotid);

mbed_error_t    fidostorage_get_appid_metadata(uint8_t const * const appid, uint32_t    appid_slot, uint8_t *data_buffer);

mbed_error_t    fidostorage_set_appid_metada(uint8_t *appid, uint32_t   appid_slot, fidostorage_appid_metadata_t const * const metadata);

#endif/*!LIBFIDOSTORAGE_H_*/

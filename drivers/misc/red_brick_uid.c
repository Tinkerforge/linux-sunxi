/*
 * red_brick_uid.c -- Expose RED Brick's UID
 *
 * Copyright (C) 2014 Matthias Bolte (matthias@tinkerforge.com)
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <plat/system.h>

#define PROC_ENTRY_NAME "red_brick_uid"
#define BASE58_MAX_STR_SIZE 8

static const char alphabet[] =
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

static void base58_encode(char *str, u32 value)
{
	u32 mod;
	char reverse_str[BASE58_MAX_STR_SIZE] = {'\0'};
	int i = 0;
	int k = 0;

	while (value >= 58) {
		mod = value % 58;
		reverse_str[i] = alphabet[mod];
		value = value / 58;
		++i;
	}

	reverse_str[i] = alphabet[value];

	for (k = 0; k <= i; k++) {
		str[k] = reverse_str[i - k];
	}

	for (; k < BASE58_MAX_STR_SIZE; k++) {
		str[k] = '\0';
	}
}

static u32 uid = 0;

u32 red_brick_get_uid(void)
{
	if (uid == 0) {
		struct sw_chip_id chip_id;

		sw_get_chip_id(&chip_id);

		uid = ((chip_id.sid_rkey0 & 0x000000ff) << 24) | (chip_id.sid_rkey3 & 0x00ffffff);

		// avoid collisions with other Brick UIDs by clearing the 31th bit, as
		// other Brick UIDs should have the 31th bit set always. avoid collisions
		// with Bricklet UIDs by setting the 30th bit to get a high UID, as
		// Bricklets have a low UID
		uid = (uid & ~(1 << 31)) | (1 << 30);
	}

	return uid;
}
EXPORT_SYMBOL(red_brick_get_uid);

static char uid_str[BASE58_MAX_STR_SIZE] = "";

const char *red_brick_get_uid_str(void)
{
	if (uid_str[0] == '\0') {
		base58_encode(uid_str, red_brick_get_uid());
	}

	return uid_str;
}
EXPORT_SYMBOL(red_brick_get_uid_str);

static int proc_read(char *buffer, char **buffer_location,
                     off_t offset, int buffer_length, int *eof, void *data)
{
	if (offset > 0) {
		return 0;
	}

	return snprintf(buffer, buffer_length, "%s\n", red_brick_get_uid_str());
}

static int __init init(void)
{
	struct proc_dir_entry *proc_uid = create_proc_entry(PROC_ENTRY_NAME, S_IRUGO, NULL);

	if (!proc_uid) {
		return -ENOMEM;
	}

	proc_uid->read_proc = proc_read;

	return 0;
}
module_init(init);

static void __exit cleanup(void)
{
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
}
module_exit(cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matthias Bolte");

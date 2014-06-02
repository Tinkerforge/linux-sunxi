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

static const char base58_alphabet[] =
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
static u32 uid;
static char uid_str[BASE58_MAX_STR_SIZE];

u32 red_brick_get_uid(void)
{
	return uid;
}

const char *red_brick_get_uid_str(void)
{
	return uid_str;
}

static void base58_encode(char *str, u32 value)
{
	u32 mod;
	char reverse_str[BASE58_MAX_STR_SIZE] = {'\0'};
	int i = 0;
	int k = 0;

	while (value >= 58) {
		mod = value % 58;
		reverse_str[i] = base58_alphabet[mod];
		value = value / 58;
		++i;
	}

	reverse_str[i] = base58_alphabet[value];

	for (k = 0; k <= i; k++) {
		str[k] = reverse_str[i - k];
	}

	for (; k < BASE58_MAX_STR_SIZE; k++) {
		str[k] = '\0';
	}
}

static int proc_uid_read(char *buffer, char **buffer_location,
                         off_t offset, int buffer_length, int *eof, void *data)
{
	if (offset > 0) {
		return 0;
	}

	return snprintf(buffer, buffer_length, "%s\n", uid_str);
}

static int __init setup(void)
{
	struct sw_chip_id chip_id;
	struct proc_dir_entry *proc_uid;

	/* read chip ID and deduce UID from it */
	sw_get_chip_id(&chip_id);

	uid = ((chip_id.sid_rkey0 & 0x000000ff) << 24) |
	       (chip_id.sid_rkey3 & 0x00ffffff);

	/* avoid collisions with other Brick UIDs by clearing the 31th bit,
	 * as other Brick UIDs should have the 31th bit set always. avoid
	 * collisions with Bricklet UIDs by setting the 30th bit to get a
	 * high UID, as Bricklets have a low UID */
	uid = (uid & ~(1 << 31)) | (1 << 30);

	/* encode the UID as base58 */
	base58_encode(uid_str, uid);

	/* register proc entry /proc/red_brick_uid */
	proc_uid = create_proc_entry(PROC_ENTRY_NAME, S_IRUGO, NULL);

	if (!proc_uid) {
		return -ENOMEM;
	}

	proc_uid->read_proc = proc_uid_read;

	return 0;
}

static void __exit cleanup(void)
{
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
}

MODULE_AUTHOR("Matthias Bolte");
MODULE_LICENSE("GPL");

module_init(setup);
module_exit(cleanup);

EXPORT_SYMBOL(red_brick_get_uid);
EXPORT_SYMBOL(red_brick_get_uid_str);

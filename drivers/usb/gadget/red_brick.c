/*
 * red_brick.c -- USB gadget RED Brick driver
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

#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/device.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>

#include "u_serial.h"

/*
 * Kbuild is not very cooperative with respect to linking separately
 * compiled library objects into one module.  So for now we won't use
 * separate compilation ... ensuring init/exit sections work to shrink
 * the runtime footprint, and giving us at least some parts of what
 * a "gcc --combine ... part1.c part2.c part3.c ... " build would.
 */
#include "composite.c"
#include "usbstring.c"
#include "config.c"
#include "epautoconf.c"

#include "f_brick.c"
#include "f_acm.c"
#include "f_serial.c"
#include "u_serial.c"

#define STRING_MANUFACTURER_IDX 0
#define STRING_PRODUCT_IDX 1
#define STRING_SERIAL_NUMBER_IDX 2

static char serial_number[8] = "";

/* string IDs are assigned dynamically */
static struct usb_string strings_dev[] = {
	[STRING_MANUFACTURER_IDX].s  = "Tinkerforge GmbH",
	[STRING_PRODUCT_IDX].s       = "RED Brick",
	[STRING_SERIAL_NUMBER_IDX].s = serial_number,
	{  } /* end of list */
};

static struct usb_gadget_strings stringtab_dev = {
	.language = 0x0409, /* en-us */
	.strings  = strings_dev,
};

static struct usb_gadget_strings *dev_strings[] = {
	&stringtab_dev,
	NULL,
};

static struct usb_device_descriptor device_desc = {
	.bLength              = sizeof(device_desc),
	.bDescriptorType      = USB_DT_DEVICE,
	.bcdUSB               = __constant_cpu_to_le16(0x0200),
	.bDeviceClass         = USB_CLASS_PER_INTERFACE,
	.idVendor             = __constant_cpu_to_le16(0x16D0),
	.idProduct            = __constant_cpu_to_le16(0x09E5),
	.bcdDevice            = __constant_cpu_to_le16(0x0110),
	.bNumConfigurations   = 1,
};

static struct usb_otg_descriptor otg_descriptor = {
	.bLength =         sizeof otg_descriptor,
	.bDescriptorType = USB_DT_OTG,

	/* REVISIT SRP-only hardware is possible, although
	 * it would not be called "OTG" ...
	 */
	.bmAttributes =    USB_OTG_SRP | USB_OTG_HNP,
};

static const struct usb_descriptor_header *otg_desc[] = {
	(struct usb_descriptor_header *)&otg_descriptor,
	NULL,
};

/*-------------------------------------------------------------------------*/

#define USE_ACM 1

static int __init red_brick_bind_config(struct usb_configuration *c)
{
	int ret;

	ret = f_brick_bind_config(c);

	if (ret < 0) {
		printk(KERN_DEBUG "could not bind Brick config\n");

		return ret;
	}

#if USE_ACM
	ret = acm_bind_config(c, 0);

	if (ret < 0) {
		printk(KERN_DEBUG "could not bind ACM config\n");

		return ret;
	}
#endif

	return 0;
}

static int red_brick_config_setup(struct usb_configuration *c,
                                  const struct usb_ctrlrequest *ctrl)
{
	struct usb_function *f = NULL;

	f = c->interface[0];

	if (f && f->setup) {
		return f->setup(f, ctrl);
	}

	return -EOPNOTSUPP;
}

static struct usb_configuration red_brick_config = {
	.label               = "foobar",
	.bConfigurationValue = 1,
	.bmAttributes        = USB_CONFIG_ATT_ONE,
	.bMaxPower           = 250, /* 500mA */
	.setup               = red_brick_config_setup,
};

static int __init red_brick_bind(struct usb_composite_dev *cdev)
{
	int ret;

	/* setup serial */
#if USE_ACM
	ret = gserial_setup(cdev->gadget, 1);

	if (ret < 0) {
		return ret;
	}
#endif

	/* allocate manufacturer string descriptor ID */
	ret = usb_string_id(cdev);

	if (ret < 0) {
		goto error;
	}

	strings_dev[STRING_MANUFACTURER_IDX].id = ret;
	device_desc.iManufacturer = ret;

	/* allocate product string descriptor ID */
	ret = usb_string_id(cdev);

	if (ret < 0) {
		goto error;
	}

	strings_dev[STRING_PRODUCT_IDX].id = ret;
	device_desc.iProduct = ret;

	/* set serial number from UID */
	snprintf(serial_number, sizeof(serial_number), "%s", red_brick_get_uid_str());

	/* allocate serial number string descriptor ID */
	ret = usb_string_id(cdev);

	if (ret < 0) {
		goto error;
	}

	strings_dev[STRING_SERIAL_NUMBER_IDX].id = ret;
	device_desc.iSerialNumber = ret;

	/* configure OTG */
	if (gadget_is_otg(cdev->gadget)) {
		red_brick_config.descriptors = otg_desc;
		red_brick_config.bmAttributes |= USB_CONFIG_ATT_WAKEUP;
	}

	/* add USB config */
	ret = usb_add_config(cdev, &red_brick_config, red_brick_bind_config);

	if (ret < 0) {
		goto error;
	}

	return 0;

error:
#if USE_ACM
	gserial_cleanup();
#endif

	return ret;
}

static int __exit red_brick_unbind(struct usb_composite_dev *cdev)
{
#if USE_ACM
	gserial_cleanup();
#endif

	return 0;
}

static struct usb_composite_driver red_brick_driver = {
	.name      = "RED Brick",
	.dev       = &device_desc,
	.strings   = dev_strings,
	.max_speed = USB_SPEED_SUPER,
	.unbind    = __exit_p(red_brick_unbind),
};

static int __init setup(void)
{
	int ret;

	ret = f_brick_setup();

	if (ret < 0) {
		return ret;
	}

	ret = usb_composite_probe(&red_brick_driver, red_brick_bind);

	if (ret < 0) {
		f_brick_cleanup();

		return ret;
	}

	return 0;
}

static void __exit cleanup(void)
{
	usb_composite_unregister(&red_brick_driver);
	f_brick_cleanup();
}

module_init(setup);
module_exit(cleanup);

MODULE_AUTHOR("Matthias Bolte");
MODULE_LICENSE("GPL");

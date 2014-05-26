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

/*-------------------------------------------------------------------------*/

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

/*-------------------------------------------------------------------------*/

/* string IDs are assigned dynamically */

#define STRING_MANUFACTURER_IDX 0
#define STRING_PRODUCT_IDX 1
#define STRING_SERIAL_NUMBER_IDX 2

static char serial_number[8] = "";

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
	.idVendor             = __constant_cpu_to_le16(0x16d0),
	.idProduct            = __constant_cpu_to_le16(0x063d),
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

/* Module */
MODULE_AUTHOR("Matthias Bolte");
MODULE_LICENSE("GPL");

/*-------------------------------------------------------------------------*/

#define USE_ACM 1

static int __init red_brick_bind_config(struct usb_configuration *c)
{
	int status;

	status = f_brick_bind_config(c);
	if (status < 0) {
		printk(KERN_DEBUG "could not bind Brick config\n");
		return status;
	}

#if USE_ACM
	status = acm_bind_config(c, 0);
	if (status < 0) {
		printk(KERN_DEBUG "could not bind ACM config\n");
		return status;
	}
#endif

	return 0;
}

static struct usb_configuration red_brick_config = {
	.label               = "foobar",
	.bConfigurationValue = 1,
	//.bmAttributes        = /*USB_CONFIG_ATT_ONE |*/ USB_CONFIG_ATT_SELFPOWER,
	.bMaxPower           = 250, /* 500mA */
};

static int __init red_brick_bind(struct usb_composite_dev *cdev)
{
	int status;

#if USE_ACM
	status = gserial_setup(cdev->gadget, 1);
	if (status < 0)
		return status;
#endif

	status = usb_string_id(cdev);
	if (status < 0)
		goto error;
	strings_dev[STRING_MANUFACTURER_IDX].id = status;
	device_desc.iManufacturer = status;

	status = usb_string_id(cdev);
	if (status < 0)
		goto error;
	strings_dev[STRING_PRODUCT_IDX].id = status;
	device_desc.iProduct = status;

	snprintf(serial_number, sizeof(serial_number), "%s", red_brick_get_uid_str());
	status = usb_string_id(cdev);
	if (status < 0)
		goto error;
	strings_dev[STRING_SERIAL_NUMBER_IDX].id = status;
	device_desc.iSerialNumber = status;

	if (gadget_is_otg(cdev->gadget)) {
		red_brick_config.descriptors = otg_desc;
		red_brick_config.bmAttributes |= USB_CONFIG_ATT_WAKEUP;
	}

	status = usb_add_config(cdev, &red_brick_config, red_brick_bind_config);
	if (status < 0)
		goto error;

	pr_info("%s\n", "RED Brick Gadget");
	return 0;

error:
#if USE_ACM
	gserial_cleanup();
#endif

	return status;
}

static int __exit red_brick_unbind(struct usb_composite_dev *cdev)
{
#if USE_ACM
	gserial_cleanup();
#endif

	return 0;
}

static struct usb_composite_driver red_brick_driver = {
	.name      = "RED Brick Gadget",
	.dev       = &device_desc,
	.strings   = dev_strings,
	.max_speed = USB_SPEED_SUPER,
	.unbind    = __exit_p(red_brick_unbind),
};

static int __init init(void)
{
	return usb_composite_probe(&red_brick_driver, red_brick_bind);
}
module_init(init);

static void __exit cleanup(void)
{
	usb_composite_unregister(&red_brick_driver);
}
module_exit(cleanup);

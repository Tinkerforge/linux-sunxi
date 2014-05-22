/*
 * f_brick.c -- Gadget function driver for Brick emulation
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


/* #define DEBUG */
/* #define VERBOSE_DEBUG */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>

#include <linux/types.h>
#include <linux/file.h>
#include <linux/device.h>
#include <linux/miscdevice.h>

#include <linux/usb.h>
#include <linux/usb_usual.h>
#include <linux/usb/ch9.h>
#include <linux/usb/f_mtp.h>

#include <plat/system.h>

#define MTP_BULK_BUFFER_SIZE       80

/* String IDs */
#define INTERFACE_STRING_INDEX	0

/* values for mtp_dev.state */
#define STATE_OFFLINE               0   /* initial state, disconnected */
#define STATE_READY                 1   /* ready for userspace calls */
#define STATE_BUSY                  2   /* processing userspace calls */
#define STATE_CANCELED              3   /* transaction canceled by host */
#define STATE_ERROR                 4   /* error from completion routine */

/* number of tx and rx requests to allocate */
#define TX_REQ_MAX 5
#define RX_REQ_MAX 5

/* ID for Microsoft MTP OS String */
#define MTP_OS_STRING_ID   0xEE

/* MTP class reqeusts */
#define MTP_REQ_CANCEL              0x64
#define MTP_REQ_GET_EXT_EVENT_DATA  0x65
#define MTP_REQ_RESET               0x66
#define MTP_REQ_GET_DEVICE_STATUS   0x67

/* constants for device status */
#define MTP_RESPONSE_OK             0x2001
#define MTP_RESPONSE_DEVICE_BUSY    0x2019

struct f_brick_dev {
	struct usb_function func;
	struct usb_composite_dev *cdev;
	spinlock_t lock;

	struct usb_ep *ep_in;
	struct usb_ep *ep_out;

	int state;

	/* synchronize access to our device file */
	atomic_t open_excl;
	/* to enforce only one ioctl at a time */
	atomic_t ioctl_excl;

	struct list_head tx_idle;

	wait_queue_head_t read_wq;
	wait_queue_head_t write_wq;
	struct usb_request *rx_req[RX_REQ_MAX];
	int rx_done;

	/* for processing MTP_SEND_FILE, MTP_RECEIVE_FILE and
	 * MTP_SEND_FILE_WITH_HEADER ioctls on a work queue
	 */
	/*struct workqueue_struct *wq;
	struct work_struct send_file_work;
	struct work_struct receive_file_work;
	struct file *xfer_file;
	loff_t xfer_file_offset;
	int64_t xfer_file_length;
	unsigned xfer_send_header;
	uint16_t xfer_command;
	uint32_t xfer_transaction_id;
	int xfer_result;*/
};

static struct usb_interface_descriptor f_brick_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	.bInterfaceNumber       = 0,
	.bNumEndpoints          = 2,
	.bInterfaceClass        = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass     = USB_SUBCLASS_VENDOR_SPEC,
	.bInterfaceProtocol     = 0,
};

static struct usb_endpoint_descriptor f_brick_hs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(/*512*/64),
};

static struct usb_endpoint_descriptor f_brick_hs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(/*512*/64),
};

static struct usb_endpoint_descriptor f_brick_fs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_endpoint_descriptor f_brick_fs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_descriptor_header *f_brick_fs_descs[] = {
	(struct usb_descriptor_header *) &f_brick_interface_desc,
	(struct usb_descriptor_header *) &f_brick_fs_in_desc,
	(struct usb_descriptor_header *) &f_brick_fs_out_desc,
	NULL,
};

static struct usb_descriptor_header *f_brick_hs_descs[] = {
	(struct usb_descriptor_header *) &f_brick_interface_desc,
	(struct usb_descriptor_header *) &f_brick_hs_in_desc,
	(struct usb_descriptor_header *) &f_brick_hs_out_desc,
	NULL,
};

static struct usb_string f_brick_string_defs[] = {
	[INTERFACE_STRING_INDEX].s = "brick",
	{ }, /* end of list */
};

static struct usb_gadget_strings f_brick_string_table = {
	.language = 0x0409, /* en-US */
	.strings  = f_brick_string_defs,
};

static struct usb_gadget_strings *f_brick_strings[] = {
	&f_brick_string_table,
	NULL,
};

/* Microsoft WinUSB OS String */
static u8 winusb_os_string[] = {
	18, /* sizeof(winusb_os_string) */
	USB_DT_STRING,
	'M', 0, 'S', 0, 'F', 0, 'T', 0, '1', 0, '0', 0, '0', 0, /* Signature field: "MSFT100" */
	1, /* vendor code */
	0, /* padding */
};

/* Microsoft Extended Configuration Descriptor Header Section */
struct winusb_ext_config_desc_header {
	__le32 dwLength;
	__u16 bcdVersion;
	__le16 wIndex;
	__u8 bCount;
	__u8 reserved[7];
};

/* Microsoft Extended Configuration Descriptor Function Section */
struct winusb_ext_config_desc_function {
	__u8 bFirstInterfaceNumber;
	__u8 bInterfaceCount;
	__u8 compatibleID[8];
	__u8 subCompatibleID[8];
	__u8 reserved[6];
};

/* MTP Extended Configuration Descriptor */
struct {
	struct winusb_ext_config_desc_header header;
	struct winusb_ext_config_desc_function function;
} winusb_ext_config_desc = {
	.header = {
		.dwLength   = __constant_cpu_to_le32(sizeof(winusb_ext_config_desc)),
		.bcdVersion = __constant_cpu_to_le16(0x0100),
		.wIndex     = __constant_cpu_to_le16(4),
		.bCount     = __constant_cpu_to_le16(1),
	},
	.function = {
		.bFirstInterfaceNumber = 0,
		.bInterfaceCount       = 1,
		.compatibleID          = { 'W', 'I', 'N', 'U', 'S', 'B' },
	},
};

static inline struct f_brick_dev *f_brick_func_to_dev(struct usb_function *f)
{
	return container_of(f, struct f_brick_dev, func);
}

static struct usb_request *f_brick_request_new(struct usb_ep *ep, int buffer_size)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_KERNEL);
	if (!req)
		return NULL;

	/* now allocate buffers for the requests */
	req->buf = kmalloc(buffer_size, GFP_KERNEL);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}
	req->length = buffer_size;

	return req;
}

static void f_brick_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static inline int f_brick_lock(atomic_t *excl)
{
	if (atomic_inc_return(excl) == 1) {
		return 0;
	} else {
		atomic_dec(excl);
		return -1;
	}
}

static inline void f_brick_unlock(atomic_t *excl)
{
	atomic_dec(excl);
}

/* add a request to the tail of a list */
static void f_brick_req_put(struct f_brick_dev *dev, struct list_head *head,
		struct usb_request *req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	list_add_tail(&req->list, head);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* remove a request from the head of a list */
static struct usb_request *f_brick_req_get(struct f_brick_dev *dev, struct list_head *head)
{
	unsigned long flags;
	struct usb_request *req;

	spin_lock_irqsave(&dev->lock, flags);
	if (list_empty(head)) {
		req = 0;
	} else {
		req = list_first_entry(head, struct usb_request, list);
		list_del(&req->list);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	return req;
}

static void f_brick_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct f_brick_dev *dev = req->context;
	printk("PPPHHH: f_brick_complete_in ep %p, req %p, dev %p\n", ep, req, dev);

	if (req->status != 0)
		dev->state = STATE_ERROR;

	f_brick_req_put(dev, &dev->tx_idle, req);

	wake_up(&dev->write_wq);
}

#define _BASE58_MAX_STR_SIZE 8

static const char _BASE58_ALPHABET[] = \
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

static void _base58_encode(char *str, u32 value) {
	u32 mod;
	char reverse_str[_BASE58_MAX_STR_SIZE] = {'\0'};
	int i = 0;
	int k = 0;

	while (value >= 58) {
		mod = value % 58;
		reverse_str[i] = _BASE58_ALPHABET[mod];
		value = value / 58;
		++i;
	}

	reverse_str[i] = _BASE58_ALPHABET[value];

	for (k = 0; k <= i; k++) {
		str[k] = reverse_str[i - k];
	}

	for (; k < _BASE58_MAX_STR_SIZE; k++) {
		str[k] = '\0';
	}
}

static void f_brick_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct f_brick_dev *dev = req->context;
	int i, status;
	struct usb_request *req2;
	u8 *buf;
	struct sw_chip_id chip_id;
	u32 uid;
	
	printk("PPPHHH: f_brick_complete_out ep %p, req %p, dev %p\n", ep, req, dev);

	dev->rx_done = 1;
	if (req->status != 0)
		dev->state = STATE_ERROR;

	printk("PPPHHH: f_brick_complete_out actual %d: ", req->actual);
	
	for (i = 0; i < req->actual; ++i) {
		printk("%02x ", ((u8*)req->buf)[i]);
	}
	
	printk("\n");

	status = usb_ep_queue(dev->ep_out, req, GFP_ATOMIC);
	if (status)
		printk("PPPHHH: error: %s queue req --> %d\n",
				dev->ep_out->name, status);

	wake_up(&dev->read_wq);

	req2 = f_brick_req_get(dev, &dev->tx_idle); // FIXME: tx_idle might be ampty
	if (req2==NULL) {
		printk("PPPHHH: error: tx_idle is empty\n");
		return;
	}

	sw_get_chip_id(&chip_id);
	printk("PPPHHH: chip_id %08x, %08x, %08x, %08x\n", chip_id.sid_rkey0, chip_id.sid_rkey1, chip_id.sid_rkey2, chip_id.sid_rkey3);

	uid = (chip_id.sid_rkey0 & 0x000000ff) << 24 | (chip_id.sid_rkey3 & 0x00ffffff);
	printk("PPPHHH: uid %08x\n", uid);

	buf = req2->buf;

	buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 0; // uid
	memcpy(buf, &uid, 4);

	buf[4] = 34; // length
	buf[5] = 253; // fid
	buf[6] = 1 << 3; 
	buf[7] = 0; 

	buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0; buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 0;  // uid
	_base58_encode((char*)&buf[8], uid);

	buf[16] = '0'; buf[17] = 0; buf[18] = 0; buf[19] = 0; buf[20] = 0; buf[21] = 0; buf[22] = 0; buf[23] = 0; // connected uid
	buf[24] = '0'; // position
	buf[25] = 1; buf[26] = 0; buf[27] = 0; // hw version
	buf[28] = 2; buf[29] = 0; buf[30] = 0; // fw version
	buf[31] = 17; buf[32] = 0; // dev ident
	buf[33] = 0; // enum type

	req2->length = 34;
	status = usb_ep_queue(dev->ep_in, req2, GFP_KERNEL);
	if (status < 0) 
		printk("PPPHHH: error2: %s queue req --> %d\n",
				dev->ep_in->name, status);
}

static int f_brick_create_bulk_endpoints(struct f_brick_dev *dev,
				struct usb_endpoint_descriptor *in_desc,
				struct usb_endpoint_descriptor *out_desc)
{
	struct usb_composite_dev *cdev = dev->cdev;
	struct usb_request *req;
	struct usb_ep *ep;
	int i;

	printk("PPPHHH: create_bulk_endpoints dev: %p\n", dev);

	ep = usb_ep_autoconfig(cdev->gadget, in_desc);
	if (!ep) {
		printk("PPPHHH: usb_ep_autoconfig for ep_in failed\n");
		return -ENODEV;
	}
	printk("PPPHHH: usb_ep_autoconfig for ep_in got %s\n", ep->name);
	ep->driver_data = dev; /* claim the endpoint */
	dev->ep_in = ep;

	ep = usb_ep_autoconfig(cdev->gadget, out_desc);
	if (!ep) {
		printk("PPPHHH: usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	printk("PPPHHH: usb_ep_autoconfig for brick ep_out got %s\n", ep->name);
	ep->driver_data = dev; /* claim the endpoint */
	dev->ep_out = ep;

	/* now allocate requests for our endpoints */
	for (i = 0; i < TX_REQ_MAX; i++) {
		req = f_brick_request_new(dev->ep_in, MTP_BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = f_brick_complete_in;
		req->context = dev;
		f_brick_req_put(dev, &dev->tx_idle, req);
	}
	for (i = 0; i < RX_REQ_MAX; i++) {
		req = f_brick_request_new(dev->ep_out, MTP_BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = f_brick_complete_out;
		req->context = dev;
		dev->rx_req[i] = req;
	}

	return 0;

fail:
	printk("PPPHHH: f_brick_bind() could not allocate requests\n");
	return -1;
}

static int f_brick_func_setup(struct usb_function *f, const struct usb_ctrlrequest *ctrl)
{
	/*struct f_brick_dev *dev = f_brick_func_to_dev(f);*/
	struct usb_composite_dev *cdev = f->config->cdev;
	int value = -EOPNOTSUPP;
	u16 w_index = le16_to_cpu(ctrl->wIndex);
	u16 w_value = le16_to_cpu(ctrl->wValue);
	u16 w_length = le16_to_cpu(ctrl->wLength);
//	unsigned long	flags;

	printk("PPPHHH: f_brick_func_setup "
			"%02x.%02x v%04x i%04x l%u\n",
			ctrl->bRequestType, ctrl->bRequest,
			w_value, w_index, w_length);

	/* Handle MTP OS string */
	if (ctrl->bRequestType ==
			(USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE)
			&& ctrl->bRequest == USB_REQ_GET_DESCRIPTOR
			&& (w_value >> 8) == USB_DT_STRING
			&& (w_value & 0xFF) == MTP_OS_STRING_ID) {
		value = (w_length < sizeof(winusb_os_string)
				? w_length : sizeof(winusb_os_string));
		memcpy(cdev->req->buf, winusb_os_string, value);
	} else if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_VENDOR) {
		/* Handle MTP OS descriptor */
		printk("PPPHHH: vendor request: %d index: %d value: %d length: %d\n",
			ctrl->bRequest, w_index, w_value, w_length);

		if (ctrl->bRequest == 1
				&& (ctrl->bRequestType & USB_DIR_IN)
				&& (w_index == 4 || w_index == 5)) {
			value = (w_length < sizeof(winusb_ext_config_desc) ?
					w_length : sizeof(winusb_ext_config_desc));
			memcpy(cdev->req->buf, &winusb_ext_config_desc, value);
		}
	} 
#if 0
	else if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS) {
		printk("PPPHHH: class request: %d index: %d value: %d length: %d\n",
			ctrl->bRequest, w_index, w_value, w_length);

		if (ctrl->bRequest == MTP_REQ_CANCEL && w_index == 0
				&& w_value == 0) {
			printk("PPPHHH: MTP_REQ_CANCEL\n");

			spin_lock_irqsave(&dev->lock, flags);
			if (dev->state == STATE_BUSY) {
				dev->state = STATE_CANCELED;
				wake_up(&dev->read_wq);
				wake_up(&dev->write_wq);
			}
			spin_unlock_irqrestore(&dev->lock, flags);

			/* We need to queue a request to read the remaining
			 *  bytes, but we don't actually need to look at
			 * the contents.
			 */
			value = w_length;
		} else if (ctrl->bRequest == MTP_REQ_GET_DEVICE_STATUS
				&& w_index == 0 && w_value == 0) {
			struct mtp_device_status *status = cdev->req->buf;
			status->wLength =
				__constant_cpu_to_le16(sizeof(*status));

			printk("PPPHHH: MTP_REQ_GET_DEVICE_STATUS\n");
			spin_lock_irqsave(&dev->lock, flags);
			/* device status is "busy" until we report
			 * the cancelation to userspace
			 */
			if (dev->state == STATE_CANCELED)
				status->wCode =
					__cpu_to_le16(MTP_RESPONSE_DEVICE_BUSY);
			else
				status->wCode =
					__cpu_to_le16(MTP_RESPONSE_OK);
			spin_unlock_irqrestore(&dev->lock, flags);
			value = sizeof(*status);
		}
	}
#endif

	/* respond with data transfer or status phase? */
	if (value >= 0) {
		int rc;
		cdev->req->zero = value < w_length;
		cdev->req->length = value;
		rc = usb_ep_queue(cdev->gadget->ep0, cdev->req, GFP_ATOMIC);
		if (rc < 0)
			printk("PPPHHH: %s: response queue error\n", __func__);
	}
	return value;
}

static int f_brick_func_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_brick_dev *dev = f_brick_func_to_dev(f);
	int			id;
	int			ret;

	dev->cdev = c->cdev;
	printk("PPPHHH: f_brick_func_bind dev: %p\n", dev);

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	f_brick_interface_desc.bInterfaceNumber = id;

	/* allocate endpoints */
	ret = f_brick_create_bulk_endpoints(dev, &f_brick_fs_in_desc, &f_brick_fs_out_desc);
	if (ret)
		return ret;

	/* support high speed hardware */
	if (gadget_is_dualspeed(c->cdev->gadget)) {
		f_brick_hs_in_desc.bEndpointAddress = f_brick_fs_in_desc.bEndpointAddress;
		f_brick_hs_out_desc.bEndpointAddress = f_brick_fs_out_desc.bEndpointAddress;
	}
	
	printk("PPPHHH: %s speed %s: IN/%s, OUT/%s\n",
			gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			f->name, dev->ep_in->name, dev->ep_out->name);
	return 0;
}

static void f_brick_func_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_brick_dev *dev = f_brick_func_to_dev(f);
	struct usb_request *req;
	int i;

	while ((req = f_brick_req_get(dev, &dev->tx_idle)))
		f_brick_request_free(req, dev->ep_in);

	for (i = 0; i < RX_REQ_MAX; i++)
		f_brick_request_free(dev->rx_req[i], dev->ep_out);

	dev->state = STATE_OFFLINE;
}

static int f_brick_func_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct f_brick_dev *dev = f_brick_func_to_dev(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	int ret, i, status;

	printk("PPPHHH: f_brick_function_set_alt intf: %d alt: %d\n", intf, alt);

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_in);
	if (ret) {
	printk("PPPHHH: f_brick_function_set_alt intf: %d alt: %d --> FAILED 1\n", intf, alt);
		return ret;
	}

	ret = usb_ep_enable(dev->ep_in);
	if (ret) {
	printk("PPPHHH: f_brick_function_set_alt intf: %d alt: %d --> FAILED 2\n", intf, alt);
		return ret;
	}

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_out);
	if (ret) {
	printk("PPPHHH: f_brick_function_set_alt intf: %d alt: %d --> FAILED 3\n", intf, alt);
		return ret;
	}

	ret = usb_ep_enable(dev->ep_out);
	if (ret) {
		usb_ep_disable(dev->ep_in);
	printk("PPPHHH: f_brick_function_set_alt intf: %d alt: %d --> FAILED 4\n", intf, alt);
		return ret;
	}

	dev->state = STATE_READY;

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	
	
	
	for (i = 0; i < RX_REQ_MAX; i++) {
		status = usb_ep_queue(dev->ep_out, dev->rx_req[i], GFP_ATOMIC);
		if (status)
			printk("PPPHHH: usb_ep_queue -> error: %s queue req --> %d\n",
					dev->ep_out->name, status);
	}
	
	
	printk("PPPHHH: f_brick_function_set_alt intf: %d alt: %d --> done\n", intf, alt);
	return 0;
}

static void f_brick_func_disable(struct usb_function *f)
{
	struct f_brick_dev *dev = f_brick_func_to_dev(f);
//	struct usb_composite_dev *cdev = dev->cdev;

	printk("PPPHHH: f_brick_func_disable\n");
	dev->state = STATE_OFFLINE;
	usb_ep_disable(dev->ep_in);
	usb_ep_disable(dev->ep_out);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);

	printk("PPPHHH: %s disabled\n", dev->func.name);
}

static int f_brick_bind_config(struct usb_configuration *c)
{
	struct f_brick_dev *dev;
	int status;

	if (f_brick_string_defs[INTERFACE_STRING_INDEX].id == 0) {
		status = usb_string_id(c->cdev);
		if (status < 0)
			return status;
		f_brick_string_defs[INTERFACE_STRING_INDEX].id = status;
	}

	/* allocate and initialize one new instance */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	spin_lock_init(&dev->lock);
	init_waitqueue_head(&dev->read_wq);
	init_waitqueue_head(&dev->write_wq);
	atomic_set(&dev->open_excl, 0);
	atomic_set(&dev->ioctl_excl, 0);
	INIT_LIST_HEAD(&dev->tx_idle);

	dev->cdev = c->cdev;
	dev->func.name = "brick";
	dev->func.strings = f_brick_strings;
	dev->func.descriptors = f_brick_fs_descs;
	dev->func.hs_descriptors = f_brick_hs_descs;
	dev->func.bind = f_brick_func_bind;
	dev->func.unbind = f_brick_func_unbind;
	dev->func.set_alt = f_brick_func_set_alt;
	dev->func.setup = f_brick_func_setup;
	dev->func.disable = f_brick_func_disable;

	status = usb_add_function(c, &dev->func);
	if (status)
		kfree(dev);

	return status;
}

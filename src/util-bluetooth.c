#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH	31
#define PF_BLUETOOTH	AF_BLUETOOTH
#endif

#define BTPROTO_L2CAP	0
#define BTPROTO_HCI	1
#define BTPROTO_SCO	2
#define BTPROTO_RFCOMM	3
#define BTPROTO_BNEP	4
#define BTPROTO_CMTP	5
#define BTPROTO_HIDP	6
#define BTPROTO_AVDTP	7

#define SOL_HCI		0
#define SOL_L2CAP	6
#define SOL_SCO		17
#define SOL_RFCOMM	18

#ifndef SOL_BLUETOOTH
#define SOL_BLUETOOTH	274
#endif

/* HCI device flags */
enum {
	HCI_UP,
	HCI_INIT,
	HCI_RUNNING,

	HCI_PSCAN,
	HCI_ISCAN,
	HCI_AUTH,
	HCI_ENCRYPT,
	HCI_INQUIRY,

	HCI_RAW,
};

typedef struct {
	unsigned char b[6];
} __attribute__((packed)) bdaddr_t;

/* BD Address type */
#define BDADDR_BREDR           0x00
#define BDADDR_LE_PUBLIC       0x01
#define BDADDR_LE_RANDOM       0x02

#define BDADDR_ANY   (&(bdaddr_t) {{0, 0, 0, 0, 0, 0}})
#define BDADDR_ALL   (&(bdaddr_t) {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}})
#define BDADDR_LOCAL (&(bdaddr_t) {{0, 0, 0, 0xff, 0xff, 0xff}})

/* Copy, swap, convert BD Address */
static inline int bacmp(const bdaddr_t *ba1, const bdaddr_t *ba2)
{
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
}
static inline void bacpy(bdaddr_t *dst, const bdaddr_t *src)
{
	memcpy(dst, src, sizeof(bdaddr_t));
}


struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short  hci_channel;
};

int bt_device_open(int dev_id)
{
	struct sockaddr_hci a;
	int dd, err;

	/* Create HCI socket */
	dd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	/* Bind socket to the HCI device */
	memset(&a, 0, sizeof(a));
	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = dev_id;
	if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0)
		goto failed;

	return dd;

failed:
	err = errno;
	close(dd);
	errno = err;

	return -1;
}

static int __other_bdaddr(int dd, int dev_id, long arg)
{
	struct hci_dev_info di = { .dev_id = dev_id };

	if (ioctl(dd, HCIGETDEVINFO, (void *) &di))
		return 0;

	if (hci_test_bit(HCI_RAW, &di.flags))
		return 0;

	return bacmp((bdaddr_t *) arg, &di.bdaddr);
}

static int __same_bdaddr(int dd, int dev_id, long arg)
{
	struct hci_dev_info di = { .dev_id = dev_id };

	if (ioctl(dd, HCIGETDEVINFO, (void *) &di))
		return 0;

	return !bacmp((bdaddr_t *) arg, &di.bdaddr);
}

int hci_get_route(const unsigned char *bdaddr)
{
	int dev_id;

	dev_id = hci_for_each_dev(HCI_UP, __other_bdaddr,
				(long) (bdaddr ? bdaddr : BDADDR_ANY));
	if (dev_id < 0)
		dev_id = hci_for_each_dev(HCI_UP, __same_bdaddr,
				(long) (bdaddr ? bdaddr : BDADDR_ANY));

	return dev_id;
}

int main(int argc, char *argv[])
{
    int fd = bt_device_open(0);

    if (fd == -1) {
        fprintf(stderr, "open(): error (%d) %s\n", errno, strerror(errno));
        exit(1);
    }
}
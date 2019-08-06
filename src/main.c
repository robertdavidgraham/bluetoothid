#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"


struct device_version
{
	unsigned version;
	unsigned revision;
	unsigned manufacturer;
	char version_string[32];
	const char *manufacturer_string;
};

int signal_received = 0;
static void sigint_handler(int sig)
{
	signal_received = sig;
}

static struct device_version
get_device_version(int dev_id)
{
	struct hci_version ver;
	char *hciver;
	int dd;
	int err;
	struct device_version result = {0};

	result.manufacturer_string = "";

	/* open this particular device. If the device isn't 'up', then
	 * this will fail */
	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		fprintf(stderr, "[-] hci%d: can't open device: %s (%d)\n",
						dev_id, strerror(errno), errno);
		return result;
	}

	/* Get the version informaton for this device */
	err = hci_read_local_version(dd, &ver, 1000);
	if (err < 0) {
		fprintf(stderr, "hci%d: can't read version: %s (%d)\n",
						dev_id, strerror(errno), errno);
		exit(1);
	}

	/* Convert the version integer into a useful string. Make
	 * sure it's NUL-terminated in case strncpy() has a problem. */
	hciver = hci_vertostr(ver.hci_ver);
	if (hciver) {
		strncpy(result.version_string, hciver, sizeof(result.version_string));
		result.version_string[sizeof(result.version_string)-1] = '\0';
		bt_free(hciver);
	} else {
		memcpy(result.version_string, "n/a", 4);
	}
	hci_close_dev(dd);

	result.version = ver.hci_ver;
	result.revision = ver.hci_rev;
	result.manufacturer = ver.manufacturer;
	result.manufacturer_string = bt_compidtostr(ver.manufacturer);

	return result;
}

static unsigned
get_bluetooth_device_count(void)
{
	struct hci_dev_list_req *dl;
	int err;
    int fd;
	unsigned result;

    /* Open a control socket to the Bluetooth subsystem */
    fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (fd < 0)
		return 0;
	
    /* Allocate memory large enough to hold all the possible
     * results. This should only be about 16 devices max */
    dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t));
	if (dl == NULL) {
		close(fd);
		return 0;
	}
	dl->dev_num = HCI_MAX_DEV;

    /* Call the ioctl to get the initial list of devices */
    err = ioctl(fd, HCIGETDEVLIST, dl);
	if (err < 0) {
		free(dl);
		close(fd);
		return 0;
	}

	result = dl->dev_num;
	free(dl);
	close(fd);
	
	return result;
}


static void 
print_dev_list(void)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;
    int err;
    int fd;

    /* Open a control socket to the Bluetooth subsystem */
    fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (fd < 0) {
		fprintf(stderr, "[-] HCI: can't open control interface\n");
        fprintf(stderr, "[-] HCI: %s\n", strerror(errno));
		exit(1);
    }
	
    /* Allocate memory large enough to hold all the possible
     * results. This should only be about 16 devices max */
    dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t));
	if (dl == NULL)
        abort();
	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

    /* Call the ioctl to get the initial list of devices */
    err = ioctl(fd, HCIGETDEVLIST, dl);
	if (err < 0) {
		perror("Can't get device list");
		free(dl);
		exit(1);
	}

    /* Query each device for detailed information */
	for (i = 0; i< dl->dev_num; i++) {
        struct hci_dev_info di;
		di.dev_id = (dr+i)->dev_id;
		ioctl(fd, HCIGETDEVINFO, &di);
        if (err < 0)
			continue;
		
        printf("%s %s %s ", di.name, 
            hci_test_bit(HCI_UP, &di.flags)?"UP":"DOWN",
            hci_test_bit(HCI_RUNNING, &di.flags)?"RUNNING":"STOPPED"
            );
        if (hci_test_bit(HCI_UP, &di.flags)) {
            struct device_version v;
			v = get_device_version(di.dev_id);
        	printf("HCIv%s(0x%x) rev(0x%x) manuf(%s %d)",
				v.version_string, 
				v.version, 
				v.revision,
				v.manufacturer_string, 
				v.manufacturer);
		}
        printf("\n" );
	}

	free(dl);
	close(fd);
}

/* Unofficial value, might still change */
#define LE_LINK		0x03

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

static int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
	size_t offset;

	if (!flags || !data)
		return -EINVAL;

	offset = 0;
	while (offset < size) {
		uint8_t len = data[offset];
		uint8_t type;

		/* Check if it is the end of the significant part */
		if (len == 0)
			break;

		if (len + offset > size)
			break;

		type = data[offset + 1];

		if (type == FLAGS_AD_TYPE) {
			*flags = data[offset + 2];
			return 0;
		}

		offset += 1 + len;
	}

	return -ENOENT;
}

static int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
	uint8_t flags;

	/* If no discovery procedure is set, all reports are treat as valid */
	if (procedure == 0)
		return 1;

	/* Read flags AD type value from the advertising report if it exists */
	if (read_flags(&flags, info->data, info->length))
		return 0;

	switch (procedure) {
	case 'l': /* Limited Discovery Procedure */
		if (flags & FLAGS_LIMITED_MODE_BIT)
			return 1;
		break;
	case 'g': /* General Discovery Procedure */
		if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT))
			return 1;
		break;
	default:
		fprintf(stderr, "Unknown discovery procedure\n");
	}

	return 0;
}

#define NEXT_BYTE(buf, offset, length) ((((offset)+1) < length) ? (buf)[(offset)++] : (-1))

static void hexdump(const unsigned char *buf, size_t offset, size_t length)
{
	size_t i;
	for (i=offset; i<length; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}
static void
decode_packet(const unsigned char *buf, size_t length)
{
	size_t offset = 0;
	size_t i;

	switch (NEXT_BYTE(buf, offset, length)) {
	case 0x04: /* HCI_EVENT_PKT */
		i = 0;
		unsigned n;
		size_t len;
		unsigned char macaddr[6];

		n = NEXT_BYTE(buf, offset, length);
		if (n != 0x3e) {
			hexdump(buf, 0, length);
			return;
		}
		len = NEXT_BYTE(buf, offset, length);
		if (length > offset + len) {
			printf("length problem\n");
			length = offset + len;
		}
		n = NEXT_BYTE(buf, offset, length);
		if (n != 0x02) {
			hexdump(buf, 0, length);
			return;
		}
		n = NEXT_BYTE(buf, offset, length);
		if (n != 0x01) {
			hexdump(buf, 0, length);
			return;
		}
		n = NEXT_BYTE(buf, offset, length);
		if (n != 0x04 && n != 0x00) {
			hexdump(buf, 0, length);
			return;
		}
		printf("-- ");
		hexdump(buf, offset, length);
		break;
	default:
		printf("UNKOWN ");
		hexdump(buf, 0, length);
	}
}
static int print_advertising_devices(int dd, uint8_t filter_type)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		printf("Could not set socket options\n");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	while (1) {
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}

		decode_packet(buf, len);

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *) ptr;

		if (meta->subevent != 0x02)
			goto done;

		/* Ignoring multiple reports */
		info = (le_advertising_info *) (meta->data + 1);
		if (check_report_filter(filter_type, info)) {
			char name[30];

			memset(name, 0, sizeof(name));

			ba2str(&info->bdaddr, addr);
			eir_parse_name(info->data, info->length,
							name, sizeof(name) - 1);

			//printf("%s %s\n", addr, name);
		}
	}

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	if (len < 0)
		return -1;

	return 0;
}


int main(int argc, char *argv[])
{
	if (argc == 1) {
		printf("usage:\n bleid dev\n bleid mon\n");
		exit(1);
	}

	/* Before we do anything else, make sure that Bluetooth devices
	 * exist in the system. */
	unsigned device_count = get_bluetooth_device_count();
	if (device_count == 0) {
		fprintf(stderr, "[-] no Bluetooth hardware devices found\n");
		exit(1);
	}

	/* If we are just listing devices and their states, then report
	 * that. */
	if (strcmp(argv[1], "dev") == 0) {
		print_dev_list();
		exit(0);
	}
	
    int dev_id;
    int dd;
	int err;
	

    /* Get the first available bluetooth device */
    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        fprintf(stderr, "[-] hci_get_route(): %s\n", strerror(errno));
        fprintf(stderr, "[-] no bluetooth devices available. Hint: hciconfig hci0 up\n");
        exit(1);
    }

	/* Open the device that we are going to use*/
    dd = hci_open_dev(dev_id);
    if (dev_id < 0 || dd < 0) {
        fprintf(stderr, "[-] hci_open_dev(): %s\n", strerror(errno));
        exit(1);
    }

	uint8_t own_type = 0x00;
	uint8_t scan_type = 0x01;
	uint8_t filter_type = 0;
	uint8_t filter_policy = 0x00;
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t filter_dup = 0; /* We want to see duplicates */

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 1000);
	if (err < 0) {
		perror("Set scan parameters failed");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
	if (err < 0) {
		perror("Enable scan failed");
		exit(1);
	}

	printf("LE Scan ...\n");

	err = print_advertising_devices(dd, filter_type);
	if (err < 0) {
		perror("Could not receive advertising events");
		exit(1);
	}

}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#define ETHER_ADDR_LEN 6

#define UDP_PORT 9999
#define BUFFER_SIZE 2048

/*


 gcc daemon_bpf.c -o daemon_bpf

 */

int open_bpf_device(const char *iface_name, uint8_t *mac) {
    char bpf_path[32];
    int bpf_fd = -1;

    // macOS dynamically allocates BPF devices; look for a free node
    for (int i = 0; i < 99; i++) {
        snprintf(bpf_path, sizeof(bpf_path), "/dev/bpf%d", i);
        bpf_fd = open(bpf_path, O_RDWR);
        if (bpf_fd >= 0) break;
    }

    if (bpf_fd < 0) {
        perror("Failed to open any /dev/bpfXX device node. Try running as sudo");
        return -1;
    }

    // Allocate buffer size for the BPF interface
    u_int buf_len = BUFFER_SIZE;
    if (ioctl(bpf_fd, BIOCSBLEN, &buf_len) < 0) {
        perror("BIOCSBLEN failed");
        close(bpf_fd);
        return -1;
    }

    // Bind the BPF file descriptor to your chosen hardware interface (e.g., en0)
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    if (ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
        perror("BIOCSETIF failed to bind interface");
        close(bpf_fd);
        return -1;
    }

    // Ensure write operations flush directly to the hardware link immediately
    u_int immediate = 1;
    ioctl(bpf_fd, BIOCIMMEDIATE, &immediate);

#if 1
	// we only want for our MAC
	struct bpf_insn insnsMAC[] = {
		{ BPF_LD + BPF_W + BPF_ABS, 0, 0, 0 },				// Dest MAC (offset 0)
		{ BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0x66fd3c78 }, 	// First 4 bytes of MAC 66:fd:3c:78:18:ff
		{ BPF_RET + BPF_K, 0, 0, 65535 },
		{ BPF_RET + BPF_K, 0, 0, 0 }
	};
	
	// we only want IPv4 packets
	struct bpf_insn insnsIPV4[] = {
		{ BPF_LD + BPF_H + BPF_ABS, 0, 0, 12 },				// Ethernet Type (offset 12)
		{ BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0x0800 },		// is type 0x0800 (IPv4)
		{ BPF_RET + BPF_K, 0, 0, 65535 },
		{ BPF_RET + BPF_K, 0, 0, 0 }
	};
	
	struct bpf_program filter = { 4, insnsIPV4 };
	ioctl(bpf_fd, BIOCSETF, &filter);
#endif

    printf("Successfully bound BPF node to interface: %s\n", iface_name);

	// get our MAC address
    struct ifaddrs *ifap, *p;

    if (getifaddrs(&ifap) != 0)
        return -1;

    for (p = ifap; p; p = p->ifa_next)
    {
        /* Check the device name */
        if ((strcmp(p->ifa_name, iface_name) == 0) &&
            (p->ifa_addr->sa_family == AF_LINK))
        {
			//printf("checking AF_LINK %s\n", p->ifa_name);
        
            struct sockaddr_dl* sdp;

            sdp = (struct sockaddr_dl*) p->ifa_addr;
            memcpy((void *)mac, sdp->sdl_data + sdp->sdl_nlen, ETHER_ADDR_LEN);
            break;
        }
    }
    freeifaddrs(ifap);

    return bpf_fd;
}

void sighandler(int signum)
{
	printf("SIGNAL %d\n", signum);

	kill(getpid(), SIGKILL);

	signal(signum, sighandler);
}

/* Generates the lookup table for the Ethernet CRC-32 polynomial */
void generate_crc32_table(uint32_t table[256]) {
    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (size_t j = 0; j < 8; j++) {
            if (c & 1) {
                c = polynomial ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        table[i] = c;
    }
}

/* Computes the IEEE 802.3 CRC-32 checksum */
uint32_t calculate_ethernet_crc32(const uint8_t *data, size_t length) {
    static uint32_t table[256];
    static int table_initialized = 0;
    
    if (!table_initialized) {
        generate_crc32_table(table);
        table_initialized = 1;
    }

    uint32_t crc = 0xFFFFFFFF; // Initial register value
    
    for (size_t i = 0; i < length; i++) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return ~crc; // Final inversion (ones' complement)
}


int main(int argc, char *argv[])
{
	uint8_t mac[ETHER_ADDR_LEN];
	
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_name (e.g., en0)>\n", argv[0]);
        return 1;
    }

	signal(SIGINT, sighandler);

    int bpf_fd = open_bpf_device(argv[1], mac);
    if (bpf_fd < 0) return 1;

    // Create the host UDP socket to talk to MAME
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in daemon_addr, mame_addr;
    socklen_t mame_addr_len = sizeof(mame_addr);
    memset(&mame_addr, 0, mame_addr_len);

    memset(&daemon_addr, 0, sizeof(daemon_addr));
    daemon_addr.sin_family = AF_INET;
    daemon_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    daemon_addr.sin_port = htons(UDP_PORT);

    if (bind(udp_fd, (struct sockaddr*)&daemon_addr, sizeof(daemon_addr)) < 0) {
        perror("UDP bind failed");
        return 1;
    }

    printf("Daemon running. \033[1m%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\033[0m now listening for MAME frames on UDP port %d...\n",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], UDP_PORT);

	uint8_t forwardingmac[6];
    uint8_t buffer[BUFFER_SIZE];
    fd_set read_fds;
	
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(bpf_fd, &read_fds);
        FD_SET(udp_fd, &read_fds);

        int max_fd = (bpf_fd > udp_fd) ? bpf_fd : udp_fd;
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) continue;

        // Path A: MAME sent an outbound Ethernet frame -> Write out to raw macOS BPF
        if (FD_ISSET(udp_fd, &read_fds)) {
            int len = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&mame_addr, &mame_addr_len);
            if (len > 0) {
                write(bpf_fd, buffer, len);
                
                uint8_t *destmac = buffer + 0;

                // keep MAC that forwarded this packet so we can reroute any reply
                forwardingmac[0] = destmac[6];
                forwardingmac[1] = destmac[7];
                forwardingmac[2] = destmac[8];
                forwardingmac[3] = destmac[9];
                forwardingmac[4] = destmac[10];
                forwardingmac[5] = destmac[11];

                printf("WRITE(%4d): destmac: \033[7m%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\033[0m srcmac: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",len,
					destmac[0],destmac[1],destmac[2],destmac[3],destmac[4],destmac[5],
					destmac[6],destmac[7],destmac[8],destmac[9],destmac[10],destmac[11]);
            }
        }

        // Path B: Privileged macOS BPF captured an incoming frame -> Forward up to MAME
        if (FD_ISSET(bpf_fd, &read_fds)) {
            int len = read(bpf_fd, buffer, BUFFER_SIZE);
            if (len > 0 && mame_addr.sin_port > 0) {
                // BPF packs frames inside a bpf_hdr structure block.
                // For simplicity here, extract the raw payload offset or forward directly if matching hardware filters.
                struct bpf_hdr *hdr = (struct bpf_hdr *)buffer;
                uint8_t *packet_data = buffer + hdr->bh_hdrlen;

				uint8_t *destmac = packet_data + 0;
				
				// if dest is this NIC
				if (destmac[0]==mac[0] &&
					destmac[1]==mac[1] &&
					destmac[2]==mac[2] &&
					destmac[3]==mac[3] &&
					destmac[4]==mac[4] &&
					destmac[5]==mac[5])
				{
					// change it to the MAC we are forwarding
					destmac[0] = forwardingmac[0];
					destmac[1] = forwardingmac[1];
					destmac[2] = forwardingmac[2];
					destmac[3] = forwardingmac[3];
					destmac[4] = forwardingmac[4];
					destmac[5] = forwardingmac[5];

					// recompute the frame check sequence
#if 0				// netdev_feth recalculates CRC
					const uint32_t fcs = calculate_ethernet_crc32(packet_data, hdr->bh_caplen - 4);
					packet_data[hdr->bh_caplen - 4] = (fcs >> 0) & 0xff;
					packet_data[hdr->bh_caplen - 3] = (fcs >> 8) & 0xff;
					packet_data[hdr->bh_caplen - 2] = (fcs >> 16) & 0xff;
					packet_data[hdr->bh_caplen - 1] = (fcs >> 24) & 0xff;
#endif

					sendto(udp_fd, packet_data, hdr->bh_caplen, 0, (struct sockaddr*)&mame_addr, mame_addr_len);

					printf("PACKET(%4d): destmac: \033[1;32m%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\033[0m srcmac: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",len,
						destmac[0],destmac[1],destmac[2],destmac[3],destmac[4],destmac[5],
						destmac[6],destmac[7],destmac[8],destmac[9],destmac[10],destmac[11]);
				}
				else
				{
					printf("\033[3;33mPACKET(%4d): destmac: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x srcmac: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n\033[0m",len,
						destmac[0],destmac[1],destmac[2],destmac[3],destmac[4],destmac[5],
						destmac[6],destmac[7],destmac[8],destmac[9],destmac[10],destmac[11]);
				}
            }
        }
    }

    close(bpf_fd);
    close(udp_fd);
    return 0;
}

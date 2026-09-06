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
#ifdef __clang__
#pragma pack(push, 1)
#endif
struct eth2
{
	uint8_t destmac[6];
	uint8_t srcmac[6];
	uint16_t type;
	
	union
	{
		struct
		{
			uint16_t hwtype,ptype;
			uint8_t hwlen,plen;
			uint16_t op;
			uint8_t srcmac[6];
			uint32_t srcip;
			uint8_t destmac[6];
			uint32_t dstip;
		} arp;

		struct
		{
			uint16_t verihl,len;
			uint16_t ident,fragoff;
			uint8_t ttl,proto;
			uint16_t checksum;
			uint32_t srcip;
			uint32_t dstip;
			
			union
			{
				struct
				{
					uint16_t srcport;
					uint16_t dstport;
					uint16_t len;
					uint16_t chksum;
				} udp;
				struct
				{
					uint16_t srcport;
					uint16_t dstport;
					uint16_t sequence;
					uint16_t ack;
				} tcp;
			};
		} ipv4;
	};
};
#ifdef __clang__
#pragma pack(pop)
#endif


int open_bpf_device(const char *iface_name, uint8_t *hostmac) {
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

	// we only want IPv4 packets
	struct bpf_insn insnsIPV4[] = {
		{ BPF_LD + BPF_H + BPF_ABS, 0, 0, 12 },				// Ethernet Type (offset 12)
		{ BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0x0800 },		// is type 0x0800 (IPv4)
		{ BPF_RET + BPF_K, 0, 0, 65535 },
		{ BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0x0806 },		// is type 0x0806 (ARP)
		{ BPF_RET + BPF_K, 0, 0, 65535 },
		{ BPF_RET + BPF_K, 0, 0, 0 }
	};
	
	struct bpf_program filter = { 6, insnsIPV4 };
	ioctl(bpf_fd, BIOCSETF, &filter);

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
            memcpy((void *)hostmac, sdp->sdl_data + sdp->sdl_nlen, ETHER_ADDR_LEN);
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

uint16_t calculate_ipv4_checksum(uint16_t *src)
{
	int32_t sum = 0;
	
	sum += ntohs(*src++);
	sum += ntohs(*src++);
	sum += ntohs(*src++);
	sum += ntohs(*src++);
	sum += ntohs(*src++);
	src++;		// skip checksum itself
	sum += ntohs(*src++);
	sum += ntohs(*src++);
	sum += ntohs(*src++);
	sum += ntohs(*src++);

	sum += (sum >> 16);

	return htons(sum ^ 0xffff);
}

void logpacket(char *label, int len, struct eth2 *ethpkt)
{
	char dstip[16];
	char srcip[16];
	char *pkind;
	char pbuff[8];

	if (ethpkt->type == ntohs(0x0806))
	{
		strcpy(dstip, inet_ntoa(*(struct in_addr *)&(ethpkt->arp.dstip)));
		strcpy(srcip,  inet_ntoa(*(struct in_addr *)&(ethpkt->arp.srcip)));
		pkind = "ARP ";
	}
	else
	if (ethpkt->type == ntohs(0x0800))
	{
		strcpy(dstip, inet_ntoa(*(struct in_addr *)&(ethpkt->ipv4.dstip)));
		strcpy(srcip,  inet_ntoa(*(struct in_addr *)&(ethpkt->ipv4.srcip)));
		
		switch(ethpkt->ipv4.proto)
		{
			case 1:
				pkind = "ICMP";
				break;
			case 6:
				pkind = "TCP ";
				break;
			case 17:
				pkind = "UDP ";
				break;
			default:
				sprintf(pbuff,"%4d", ethpkt->ipv4.proto);
				pkind = pbuff;
				break;
		}
	}
		
	printf("%s(%4d): [%s] destmac: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x %s srcmac: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x  %s\033[0m\n",
		label, len, pkind,
		ethpkt->destmac[0],ethpkt->destmac[1],ethpkt->destmac[2],ethpkt->destmac[3],ethpkt->destmac[4],ethpkt->destmac[5],
		dstip,
		ethpkt->srcmac[0],ethpkt->srcmac[1],ethpkt->srcmac[2],ethpkt->srcmac[3],ethpkt->srcmac[4],ethpkt->srcmac[5],
		srcip);
}

int main(int argc, char *argv[])
{
	uint8_t hostmac[ETHER_ADDR_LEN];
	
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_name (e.g., en0)>\n", argv[0]);
        return 1;
    }

	signal(SIGINT, sighandler);

    int bpf_fd = open_bpf_device(argv[1], hostmac);
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
		hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5], UDP_PORT);

	uint8_t forwardingmac[6] = {0,0,0,0,0,0};
	uint32_t forwardingip = 0x08040201;
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
            
                struct eth2 *ethpkt = (struct eth2 *)buffer;

                // keep MAC that forwarded this packet so we can reroute any reply
                forwardingmac[0] = ethpkt->srcmac[0];
                forwardingmac[1] = ethpkt->srcmac[1];
                forwardingmac[2] = ethpkt->srcmac[2];
                forwardingmac[3] = ethpkt->srcmac[3];
                forwardingmac[4] = ethpkt->srcmac[4];
                forwardingmac[5] = ethpkt->srcmac[5];
                forwardingip = ethpkt->ipv4.srcip;
                
  //              ethpkt->ipv4.srcip = htonl(0xc0a801b9);
                
                logpacket("WRITE\033[7m", len, ethpkt);
                
                write(bpf_fd, buffer, len);

                for(int i=0; i<len; i++)
                {
					printf("%2.2x ", buffer[i]);
                }
                printf("\n");
            }
        }

        // Path B: Privileged macOS BPF captured an incoming frame -> Forward up to MAME
        if (FD_ISSET(bpf_fd, &read_fds)) {
        
			int len = read(bpf_fd, buffer, BUFFER_SIZE);
			struct bpf_hdr *hdr = (struct bpf_hdr *)buffer;

			// NB we may have read >1 packet
            while ((len > 0) && hdr->bh_hdrlen == 18 && (mame_addr.sin_port > 0))
            {
            
				printf("remain = %d hdrlen = %d caplen = %d\n", len, hdr->bh_hdrlen, hdr->bh_caplen);
            
                // BPF packs frames inside a bpf_hdr structure block.
                // For simplicity here, extract the raw payload offset or forward directly if matching hardware filters.
                uint8_t *packet_data = (uint8_t *)hdr + hdr->bh_hdrlen;
				struct eth2 *ethpkt = (struct eth2 *)packet_data;

				// ignore services we know nothing about
				if (ethpkt->ipv4.proto == 17 && (ethpkt->ipv4.udp.srcport == htons(53) || ethpkt->ipv4.udp.srcport == htons(5353)))
				{
					printf("\033[7mPORT:%4d IGNORED ", ntohs(ethpkt->ipv4.udp.srcport));
					logpacket("\033[0;32mPACKET", len, ethpkt);
				}
				else
				// if dest is this NIC
				if (ethpkt->destmac[0]==hostmac[0] &&
					ethpkt->destmac[1]==hostmac[1] &&
					ethpkt->destmac[2]==hostmac[2] &&
					ethpkt->destmac[3]==hostmac[3] &&
					ethpkt->destmac[4]==hostmac[4] &&
					ethpkt->destmac[5]==hostmac[5])
				{
					// change it to the MAC we are forwarding
					ethpkt->destmac[0] = forwardingmac[0];
					ethpkt->destmac[1] = forwardingmac[1];
					ethpkt->destmac[2] = forwardingmac[2];
					ethpkt->destmac[3] = forwardingmac[3];
					ethpkt->destmac[4] = forwardingmac[4];
					ethpkt->destmac[5] = forwardingmac[5];

					if (ethpkt->type == ntohs(0x0800))
					{
						ethpkt->ipv4.dstip = forwardingip;
						ethpkt->ipv4.checksum = calculate_ipv4_checksum((uint16_t *)&ethpkt->ipv4);
					}
					else
					if (ethpkt->type == ntohs(0x0806))
					{
						ethpkt->arp.dstip = forwardingip;
					}

					// recompute the frame check sequence
#if 0				// netdev_feth recalculates CRC
					const uint32_t fcs = calculate_ethernet_crc32(packet_data, hdr->bh_caplen - 4);
					packet_data[hdr->bh_caplen - 4] = (fcs >> 0) & 0xff;
					packet_data[hdr->bh_caplen - 3] = (fcs >> 8) & 0xff;
					packet_data[hdr->bh_caplen - 2] = (fcs >> 16) & 0xff;
					packet_data[hdr->bh_caplen - 1] = (fcs >> 24) & 0xff;
#endif

					sendto(udp_fd, packet_data, hdr->bh_caplen, 0, (struct sockaddr*)&mame_addr, mame_addr_len);
					logpacket("\033[1;32mPACKET", len, ethpkt);

					for(int i=0; i<len; i++)
					{
						printf("%2.2x ", packet_data[i]);
					}
					printf("\n");
				}
				else
				// if dest is broadcast
				if (ethpkt->destmac[0]==0xff && ethpkt->destmac[1]==0xff && ethpkt->destmac[2]==0xff &&
					ethpkt->destmac[3]==0xff && ethpkt->destmac[4]==0xff && ethpkt->destmac[5]==0xff &&
					ethpkt->ipv4.srcip != forwardingip)
				{
					sendto(udp_fd, packet_data, hdr->bh_caplen, 0, (struct sockaddr*)&mame_addr, mame_addr_len);
					logpacket("\033[1;32;40mBRCAST", len, ethpkt);

					for(int i=0; i<len; i++)
					{
						printf("%2.2x ", packet_data[i]);
					}
					printf("\n");
				}
				else	// not for us
				if (1)
				{
					logpacket("\033[0;31mPACKET", len, ethpkt);
				}
				
				len -= hdr->bh_hdrlen + hdr->bh_caplen;
				hdr = (struct bpf_hdr *)((uint8_t *)hdr + hdr->bh_hdrlen + hdr->bh_caplen);
				
				if (len)
					printf("MORE packets STUFF: %d\n", len);
            }
			printf("***** remain = %d hdrlen = %d caplen = %d\n", len, hdr->bh_hdrlen, hdr->bh_caplen);
            
        }
    }

    close(bpf_fd);
    close(udp_fd);
    return 0;
}

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>

#define BUF_SIZE 100

#define ICMPv6_HDRLEN 32
#define ICMPv6_NXTHDR 58

int my_socket = 0;
void* buffer = NULL;
char DEVICE[30];
unsigned char src_mac[6];

void sigint(int signum);

int filterMacBroadcast(const unsigned char* bytes) {
    for (int i = 0; i < 6; i++)
        if (bytes[i] != 0xff)
            return 0;
    return 1;
}

int filterArp(const unsigned char* bytes) {
    return bytes[12] == 0x08 && bytes[13] == 0x06;
}

int filterIPv4(const unsigned char* bytes) {
    return bytes[16] == 0x08 && bytes[17] == 0x00;
}

int filterRequest(const unsigned char* bytes) {
    return bytes[20] == 0x00 && bytes[21] == 0x01;
}

int filterSenderIpBroadcast(const unsigned char* bytes) {
    for (int i = 28; i < 32; i++)
        if (bytes[i] != 0x00)
            return 0;
    return 1;
}

int filterTargetMacBroadcast(const unsigned char* bytes) {
    for (int i = 28; i < 32; i++)
        if (bytes[i] != 0x00)
            return 0;
    return 1;
}

int filterMessageIPv4(const unsigned char* bytes) {
    return filterMacBroadcast(bytes) &&
        filterArp(bytes) &&
        filterIPv4(bytes) &&
        filterRequest(bytes) &&
        filterSenderIpBroadcast(bytes) &&
        filterTargetMacBroadcast(bytes);
}

void fillDestination(unsigned char* bytes) {
    for (int i = 0; i < 6; i++) {
        bytes[i] = bytes[i + 6];
    }
}

void fillSource(unsigned char* bytes) {
    for (int i = 0; i < 6; i++) {
        bytes[i + 6] = src_mac[i];
    }
}

void fillOpcode(unsigned char* bytes) {
    bytes[21] = 0x02;
}

void fillTargetMac(unsigned char* bytes) {
    for (int i = 0; i < 6; i++) {
        bytes[i + 32] = bytes[i + 22];
    }
}

void fillSenderMac(unsigned char* bytes) {
    for (int i = 0; i < 6; i++) {
        bytes[i + 22] = src_mac[i];
    }
}

void fillSenderIp(unsigned char* bytes) {
    for (int i = 0; i < 4; i++) {
        bytes[i + 28] = bytes[i + 38];
    }
}

void fillTargetIp(unsigned char* bytes) {
    for (int i = 0; i < 4; i++) {
        bytes[i + 38] = 0x00;
    }
}

void prepareResponseIPv4(unsigned char* bytes) {
    fillDestination(bytes);
    fillSource(bytes);
    fillOpcode(bytes);
    fillTargetMac(bytes);
    fillSenderMac(bytes);
    fillSenderIp(bytes);
    fillTargetIp(bytes);
}

// IPv6 filter

int filterMacMulticast(const unsigned char* bytes) {
    const unsigned char IPv6mcast_ff[] = { 0x33, 0x33, 0xff };
    for (int i = 0; i < 3; i++)
        if (bytes[i] != IPv6mcast_ff[i])
            return 0;
    return 1;
}

int filterIpv6(const unsigned char* bytes) {
    return bytes[12] == 0x86 && bytes[13] == 0xdd && (bytes[14] >> 4) == 6;
}

int filterICMPv6(const unsigned char* bytes) {
    return bytes[20] == 0x3a;
}

int filterSourceIPv6(const unsigned char* bytes) {
    for (int i = 0; i < 16; i++)
        if (bytes[i + 22] != 0x00)
            return 0;
    return 1;
}

int filterNeighbourSolicitation(const unsigned char* bytes) {
    return bytes[54] == 0x87;
}

int filterMessageIPv6(const unsigned char* bytes) {
    return filterMacMulticast(bytes) &&
        filterIpv6(bytes) &&
        filterICMPv6(bytes) &&
        filterSourceIPv6(bytes) &&
        filterNeighbourSolicitation(bytes);
}

// IPv6 prepare

void fillMacMulticast(unsigned char* bytes) {
    const unsigned char IPv6mcast_01[] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };
    for (int i = 0; i < 6; i++)
        bytes[i] = IPv6mcast_01[i];
}

void fillPayloadLength(unsigned char* bytes) {
    bytes[18] = 0x00;
    bytes[19] = 0x20;
}

void fillHopLimit(unsigned char* bytes) {
    bytes[21] = 0xff;
}

void fillSourceIPv6(unsigned char* bytes) {
    for (int i = 0; i < 16; i++)
        bytes[i + 22] = bytes[i + 62];
}

void fillDestinationIPv6(unsigned char* bytes) {
    const unsigned char destIPv6[] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    for (int i = 0; i < 16; i++)
        bytes[i + 38] = destIPv6[i];
}

void fillNeighbourAdvertisement(unsigned char* bytes) {
    bytes[54] = 0x88;
}

void fillOverrideFlag(unsigned char* bytes) {
    bytes[58] = 0x20;
    bytes[59] = 0x00;
    bytes[60] = 0x00;
    bytes[61] = 0x00;
}

void fillOptionType(unsigned char* bytes) {
    bytes[78] = 0x02;
}

void fillOptionLength(unsigned char* bytes) {
    bytes[79] = 0x01;
}

void fillOptionAddress(unsigned char* bytes) {
    for (int i = 0; i < 6; i++) {
        bytes[i + 80] = src_mac[i];
    }
}

uint16_t checksum(uint16_t* addr, int len) {

    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t*)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

uint16_t icmpv6checksum(const unsigned char* bytes) {
    unsigned char buf[BUF_SIZE] = { 0 };
    unsigned char* ptr = buf;
    int checksumLen = 0;

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, bytes + 22, 16);
    ptr += 16;
    checksumLen += 16;

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, bytes + 38, 16);
    ptr += 16;
    checksumLen += 16;

    // Copy Upper Layer Packet length into buf (32 bits).
    // Should not be greater than 65535 (i.e., 2 bytes).
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = ICMPv6_HDRLEN / 256;
    ptr++;
    *ptr = ICMPv6_HDRLEN % 256;
    ptr++;
    checksumLen += 4;

    // Copy zero field to buf (24 bits)
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    checksumLen += 3;

    // Copy next header field to buf (8 bits)
    *ptr = ICMPv6_NXTHDR; ptr++; checksumLen++;

    // Copy ICMPv6 type to buf (8 bits)
    memcpy(ptr, bytes + 54, 1);
    ptr++;
    checksumLen++;

    // Copy ICMPv6 code to buf (8 bits)
    memcpy(ptr, bytes + 55, 1);
    ptr++;
    checksumLen++;

    // Copy ICMPv6 checksum to buf (16 bits)
    // Zero, since we don't know it yet.
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    checksumLen += 2;

    // Copy ICMPv6 flags to buf (16 bits)
    memcpy(ptr, bytes + 58, 4);
    ptr += 4;
    checksumLen += 4;

    // Copy ICMPv6 target address to buf
    memcpy(ptr, bytes + 62, 16);
    ptr += 16;
    checksumLen += 16;

    // Copy ICMPv6 options to buf
    memcpy(ptr, bytes + 78, 8);
    ptr += 8;
    checksumLen += 8;

    return checksum((uint16_t*)buf, checksumLen);
}

void fillChecksum(unsigned char* bytes) {
    uint16_t sum = icmpv6checksum(bytes);

    // reverse bytes
    bytes[56] = sum;
    bytes[57] = sum >> 8;
}

void prepareResponseIPv6(unsigned char* bytes) {
    fillMacMulticast(bytes);
    fillSource(bytes);
    fillPayloadLength(bytes);
    fillHopLimit(bytes);
    fillSourceIPv6(bytes);
    fillDestinationIPv6(bytes);
    fillNeighbourAdvertisement(bytes);
    fillOverrideFlag(bytes);
    fillOptionType(bytes);
    fillOptionLength(bytes);
    fillOptionAddress(bytes);
    fillChecksum(bytes);
}

void printBytes(unsigned char* message, int lineLength[], int size) {
    int byte = 0;
    for (int i = 0; i < size; i++) {
        printf("\n\t");
        for (int j = 0; j < lineLength[i]; j++) {
            printf("%02X ", message[byte]);
            byte++;
        }
    }
}

void printIPv4(unsigned char* message) {
    int lineLength[] = { 6, 6, 2, 2, 2, 1, 1, 2, 6, 4, 6, 4 };
    printBytes(message, lineLength, 12);
}

void printIPv6req(unsigned char* message) {
    int lineLength[] = { 6, 6, 2, 4, 2, 1, 1, 16, 16, 1, 1, 2, 4, 16 };
    printBytes(message, lineLength, 14);
}

void printIPv6resp(unsigned char* message) {
    int lineLength[] = { 6, 6, 2, 4, 2, 1, 1, 16, 16, 1, 1, 2, 4, 16, 1, 1, 6 };
    printBytes(message, lineLength, 17);
}

// first byte of buffer must be the first byte of destination MAC address
// ignores no-ARPProbe frames
// modifies buffer in-place to response
size_t processMessage(void* buffer) {
    unsigned char* bytes = (unsigned char*)buffer;
    if (filterMessageIPv4(bytes)) {
        printf("\n\nIPv4 Probe: ");
        printIPv4(bytes);
        prepareResponseIPv4(bytes);
        printf("\nIPv4 Response: ");
        printIPv4(bytes);
        return 42;
    }

    if (filterMessageIPv6(bytes)) {
        printf("\n\nIPv6 NS: ");
        printIPv6req(bytes);
        prepareResponseIPv6(bytes);
        printf("\nIPv6 NA: ");
        printIPv6resp(bytes);
        return 86;
    }

    return 0;
}

int main(int argc, char* argv[]) {

    if(argc<2||argc>2){
        printf("Give network interface name...");
        exit(1);
    }

    strcpy(DEVICE, argv[1]);

    buffer = (void*)malloc(BUF_SIZE);

    struct ifreq ifr;
    struct sockaddr_ll socket_address;
    int ifindex = 0;
    int i;
    int length;

    printf("Server started, entering initialiation phase...\n");

    // OPEN SOCKET
    my_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (my_socket == -1) {
        perror("socket():");
        exit(1);
    }
    printf("Successfully opened socket: %i\n", my_socket);

    strncpy(ifr.ifr_name, DEVICE, IFNAMSIZ);
    if (ioctl(my_socket, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    ifindex = ifr.ifr_ifindex;
    printf("Successfully got interface index: %i\n", ifindex);

    if (ioctl(my_socket, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    for (i = 0; i < 6; i++) {
        src_mac[i] = ifr.ifr_hwaddr.sa_data[i];
    }

    printf("Successfully got our MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = ARPHRD_ETHER;
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = 0;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    signal(SIGINT, sigint);

    printf("Waiting for packets ... \n");

    while (1) {
        length = recvfrom(my_socket, buffer, BUF_SIZE, 0, NULL, NULL);
        if (length == -1)
        {
            exit(1);
        }

        size_t bytesToSend = processMessage(buffer);
        if(bytesToSend) {
            if(sendto(my_socket, buffer, bytesToSend, 0, (const struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))<0)
            {
                printf("error in sending....errno=%d\n", errno);
                return -1;
            }
        }
    }
}

void sigint(int signum) {
    struct ifreq ifr;

    if (my_socket == -1)
        return;

    strncpy(ifr.ifr_name, DEVICE, IFNAMSIZ);
    ioctl(my_socket, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags &= ~IFF_PROMISC;
    ioctl(my_socket, SIOCSIFFLAGS, &ifr);
    close(my_socket);
    free(buffer);
    printf("Server terminating....\n");
    exit(0);
}

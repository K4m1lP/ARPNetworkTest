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

#define BUF_SIZE 100
#define SEND_BUFF_SIZE 42

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

// IPv6

int filterIpv6(const unsigned char* bytes) {
    return bytes[12] == 0x86 && bytes[13] == 0xdd;
}

int filterMessage(const unsigned char* bytes) {
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

// first byte of buffer must be the first byte of destination MAC address
// ignores no-ARPProbe frames
// modifies buffer in-place to response
int processMessage(void* buffer) {
    unsigned char* bytes = buffer;
    if (!filterMessage(bytes))
        return 0;

    fillDestination(bytes);
    fillSource(bytes);
    fillOpcode(bytes);
    fillTargetMac(bytes);
    fillSenderMac(bytes);
    fillSenderIp(bytes);
    fillTargetIp(bytes);
    return 1;
}

void printMessage(unsigned char* message) {
    int lineLength[] = { 6, 6, 2, 2, 2, 1, 1, 2, 6, 4, 6, 4 };
    int byte = 0;
    for (int i = 0; i < 12; i++) {
        printf("\n");
        for (int j = 0; j < lineLength[i]; j++) {
            printf("%02X ", message[byte]);
            byte++;
        }
    }
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
        unsigned char original[BUF_SIZE];
        memcpy(original, buffer, BUF_SIZE);

        if (filterIpv6(buffer)) {
            printf("IPv6\n\n");
        }

        if(processMessage(buffer)==1) {
            printf("In: \n");
            printMessage(original);
            printf("Out: \n");
            printMessage(buffer);
            printf("\n\n");
            if(sendto(my_socket, buffer, SEND_BUFF_SIZE, 0, (const struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))<0)
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
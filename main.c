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

#define BUF_SIZE 42

int my_socket = 0;
void* buffer = NULL;
char DEVICE[30];
unsigned char src_mac[6];

void sigint(int signum);

int main(int argc, char* argv[]) {

    strcpy(DEVICE, argv[1]);

    buffer = (void*)malloc(BUF_SIZE);

    struct ifreq ifr;
    struct sockaddr_ll socket_address;
    int ifindex = 0;
    int i;
    int length;
    int sent;

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
        printf("Something was received ...\n");

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
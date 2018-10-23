#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <cstring>

// u_short computeChecksum(u_short *buf, int count) {
//     register u_long sum = 0;
//     
//     while (count--) {
//         sum += *buf++;
//         if (sum & 0xFFFF0000) {
//             sum &= 0xFFFF;
//             sum++;
//         }
//     }
//     
//     return ~(sum & 0xFFFF);
// }

int main(){
    int packet_socket;
    //get list of interface addresses. This is a linked list. Next
    //pointer is in ifa_next, interface name is in ifa_name, address is
    //in ifa_addr. You will have multiple entries in the list with the
    //same name, if the same interface has multiple addresses. This is
    //common since most interfaces will have a MAC, IPv4, and IPv6
    //address. You can use the names to match up which IPv4 address goes
    //with which MAC address.
    
    struct addressPair {
        u_int8_t mac[6];
        struct in_addr ip;
        char interfaceName[30];
        int fileDescriptor;
    };
    struct addressPair addresses[4];
    
    struct ifaddrs *ifaddr, *tmp;
    if(getifaddrs(&ifaddr)==-1){
        perror("getifaddrs");
        return 1;
    }
    
    fd_set sockets; // a set of file descriptors
    FD_ZERO(&sockets);
    char ourInterfaceName[10];
    
    
    
    //have the list, loop over the list
    for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
        //Check if this is a packet address, there will be one per
        //interface.  There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list for example to get a list
        //of our own IP addresses
        if(tmp->ifa_addr->sa_family==AF_PACKET){
            printf("Interface: %s\n",tmp->ifa_name);
            //create a packet socket on interface r?-eth1
            
            strncpy(ourInterfaceName, tmp->ifa_name, 2);
            
            
            if(strncmp(tmp->ifa_name, "lo", 2)){
                struct sockaddr_ll * sockaddr = (sockaddr_ll *)(tmp->ifa_addr);
                char interfaceNumber = tmp->ifa_name[strlen(tmp->ifa_name) - 1];
                memcpy(&(addresses[atoi(&interfaceNumber)].mac), sockaddr->sll_addr, 6*sizeof(u_int8_t));
                memcpy(&(addresses[atoi(&interfaceNumber)].interfaceName), tmp->ifa_name, 30);
                
                printf("Our Mac : %s\n", ether_ntoa((struct ether_addr *) addresses[atoi(&interfaceNumber)].mac));
                
                
                printf("Creating Socket on interface %s\n",tmp->ifa_name);
                //create a packet socket
                //AF_PACKET makes it a packet socket
                //SOCK_RAW makes it so we get the entire packet
                //could also use SOCK_DGRAM to cut off link layer header
                //ETH_P_ALL indicates we want all (upper layer) protocols
                //we could specify just a specific one
                packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                if(packet_socket<0){
                    perror("socket");
                    return 2;
                }
                addresses[atoi(&interfaceNumber)].fileDescriptor = packet_socket;
                
                //Bind the socket to the address, so we only get packets
                //recieved on this specific interface. For packet sockets, the
                //address structure is a struct sockaddr_ll (see the man page
                //for "packet"), but of course bind takes a struct sockaddr.
                //Here, we can use the sockaddr we got from getifaddrs (which
                //we could convert to sockaddr_ll if we needed to)
                if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
                    perror("bind");
                }
                FD_SET(packet_socket, &sockets);
            }
        } else if (tmp->ifa_addr->sa_family == AF_INET) {
            if(strncmp(tmp->ifa_name, "lo", 2)){
                struct sockaddr_in * sockaddrIP = (sockaddr_in *)(tmp->ifa_addr);
                
                char interfaceNumber = tmp->ifa_name[strlen(tmp->ifa_name) - 1];
                addresses[atoi(&interfaceNumber)].ip.s_addr = sockaddrIP->sin_addr.s_addr;
                printf("Our IP: %s\n", inet_ntoa(addresses[atoi(&interfaceNumber)].ip));
            }
        }
    }
    //loop and recieve packets. We are only looking at one interface,
    //for the project you will probably want to look at more (to do so,
    //a good way is to have one socket per interface and use select to
    //see which ones have data)
    printf("Ready to recieve now\n");
    while(1){
        char packet[1500];
        struct sockaddr_ll sourceAddr;
        socklen_t recvaddrlen =sizeof(struct sockaddr_ll);
        
        fd_set tmp_set = sockets;
        select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
        //we can use recv, since the addresses are in the packet, but we
        //use recvfrom because it gives us an easy way to determine if
        //this packet is incoming or outgoing (when using ETH_P_ALL, we
        //see packets in both directions. Only outgoing can be seen when
        //using a packet socket with some specific protocol)
        
        //int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
        
        //ignore outgoing packets (we can't disable some from being sent
        //by the OS automatically, for example ICMP port unreachable
        //messages, so we will just ignore them here)
        if(sourceAddr.sll_pkttype==PACKET_OUTGOING)
            continue;
        //start processing all others
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &tmp_set)) {
                int packetSize = recvfrom(i, packet, 1500, 0, (struct sockaddr*) &sourceAddr, &recvaddrlen);
                printf("Got a %d byte packet from socket %d\n", packetSize, i);
                
                int isOurIp = 0;
                struct in_addr destinationIp;
                
                struct ether_header *ether;
                ether = (struct ether_header *)packet;
                
                if (htons(sourceAddr.sll_protocol) == ETH_P_ARP) {
                    // do arp stuff
                    printf("ARP PACKET!!!\n");
                    
                    struct ether_arp *arp;
                    
                    arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
                    
                    unsigned long tpa;
                    memcpy(&tpa, arp->arp_tpa, 4);
                    struct in_addr tpaStruct;
                    tpaStruct.s_addr = tpa;
                    destinationIp.s_addr = tpa;
                    
                    for (int z = 0; z < 4; z++) {
                        char address[50];
                        strcpy(address, inet_ntoa(addresses[z].ip));
                        char tpaAddress[50];
                        strcpy(tpaAddress, inet_ntoa(tpaStruct));

                        if (strcmp(address, tpaAddress) == 0) {
                            isOurIp = 1;
                            break;
                        }
                    }
                } else if (htons(sourceAddr.sll_protocol) == 0x800) {
                    struct ip *ipHeader;
                    ipHeader = (struct ip *)(packet + sizeof(struct ether_header) );

                    destinationIp.s_addr = ipHeader->ip_dst.s_addr;

                    for (int z = 0; z < 4; z++) {
                        char address[50];
                        strcpy(address, inet_ntoa(addresses[z].ip));
                        char tpaAddress[50];
                        strcpy(tpaAddress, inet_ntoa(ipHeader->ip_dst));

                        if (strcmp(address, tpaAddress) == 0) {
                            isOurIp = 1;
                            break;
                        }
                    }
                }
                
                
                if (isOurIp) {
                    if (htons(sourceAddr.sll_protocol) == ETH_P_ARP) {
                        // do arp stuff
                        struct ether_arp *arp;
                        arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

                        int addressIndex = 0;
                        unsigned long tpa;
                        memcpy(&tpa, arp->arp_tpa, 4);
                        struct in_addr tpaStruct;
                        tpaStruct.s_addr = tpa;
                        for (int z = 0; z < 4; z++) {

                            char address[50];
                            strcpy(address, inet_ntoa(addresses[z].ip));
                            char tpaAddress[50];
                            strcpy(tpaAddress, inet_ntoa(tpaStruct));

                            if (strcmp(address, tpaAddress) == 0) {
                                addressIndex = z;
                                break;
                            }
                        }

                        memcpy(ether->ether_dhost, ether->ether_shost, 6*sizeof(u_int8_t));
                        memcpy(ether->ether_shost, &(addresses[addressIndex].mac), 6*sizeof(u_int8_t));
                        
                        struct in_addr spa;
                        memcpy(&(spa.s_addr), arp->arp_spa, 4);
                        struct in_addr tpa2;
                        memcpy(&(tpa2.s_addr), arp->arp_tpa, 4);
                        
                        memcpy(arp->arp_tha, arp->arp_sha, 6);
                        memcpy(arp->arp_sha, &(addresses[addressIndex].mac), 6);
                        u_char swapSenderIP[4];
                        memcpy(swapSenderIP, arp->arp_tpa, 4);
                        memcpy(arp->arp_tpa, arp->arp_spa, 4);
                        memcpy(arp->arp_spa, swapSenderIP, 4);

                        memcpy(&(spa.s_addr), arp->arp_spa, 4);
                        memcpy(&(tpa2.s_addr), arp->arp_tpa, 4);

                        arp->ea_hdr.ar_op = htons(ARPOP_REPLY);

                        send(i, packet, packetSize, 0);

                    } else if (htons(sourceAddr.sll_protocol) == 0x800) {
                        // Need to figure out which protocol this IP packet is for
                        struct ip *ipHeader;
                        struct icmp *icmpHeader;
                        
                        ipHeader = (struct ip *)(packet + sizeof(struct ether_header) );
                        
                        // if it's an ICMP packet
                        if (ipHeader->ip_p == 1) {
                            icmpHeader = (struct icmp *)(packet + sizeof(struct ether_header) + sizeof(struct ip) );

                            u_int8_t swap[6];
                            memcpy(swap, ether->ether_dhost, 6*sizeof(u_int8_t));
                            memcpy(ether->ether_dhost, ether->ether_shost, 6*sizeof(u_int8_t));
                            memcpy(ether->ether_shost, swap, 6*sizeof(u_int8_t));

                            struct in_addr swapIp;
                            swapIp.s_addr = ipHeader->ip_dst.s_addr;
                            ipHeader->ip_dst.s_addr = ipHeader->ip_src.s_addr;
                            ipHeader->ip_src.s_addr = swapIp.s_addr;

                            icmpHeader->icmp_type = 0;

                            send(i, packet, packetSize, 0);
                        }
                    }
                } else {
                    char filename[50];
                    strcpy(filename, ourInterfaceName);
                    strcat(filename,"-table.txt");
                    FILE *f = fopen(filename, "r");
                    
                    char destinationIpStr[50];
                    strcpy(destinationIpStr, inet_ntoa(destinationIp));
                    char line[50];
                    char interface[50];
                    while(fgets(line, 50, f) != NULL) {
                        if (strncmp(line+9, "1", 1) == 0) {
                            if (strncmp(destinationIpStr, line, 4) == 0) {
                                // we found the matching entry for the destination IP
                                strncpy(interface, (line + strlen(line) - 8), 7);
                                break;
                            }
                        } else {
                            if (strncmp(destinationIpStr, line, 6) == 0) {
                                // we found the matching entry for the destination IP
                                strncpy(interface, (line + strlen(line) - 8), 7);
                                break;
                            }
                        }
                    }
                    fclose(f);
                    
                    //THIS IS WHERE WE'LL PICK UP
                    char arpRequest[1500];
                    struct ether_header *sendEther;
                    sendEther = (struct ether_header *)arpRequest;
                    struct ether_arp *sendArp;
                    sendArp = (struct ether_arp *)(arpRequest + sizeof(struct ether_header));
                    
                    int addressIndex = 0;
                    for (int z = 0; z < 4; z++) {
                        if (strcmp(interface, addresses[z].interfaceName) == 0) {
                            memcpy(sendEther->ether_shost, addresses[z].mac, 6);
                            addressIndex = z;
                            break;
                        }
                    }
                    
                    u_int64_t broadcastAddr = 0xffffffffffff;
                    
                    memcpy(sendEther->ether_dhost, &broadcastAddr, 6);
                    
                    sendEther->ether_type = htons(ETHERTYPE_ARP);
                    
                    // ARP HEADER
                    
                    sendArp->ea_hdr.ar_hrd = htons(1);
                    sendArp->ea_hdr.ar_pro = htons(0x800);
                    sendArp->ea_hdr.ar_hln = 6;
                    sendArp->ea_hdr.ar_pln = 4;
                    sendArp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
                    memcpy(sendArp->arp_sha, &(addresses[addressIndex].mac), 6);
                    memcpy(sendArp->arp_spa, &(addresses[addressIndex].ip.s_addr), 4);
                    u_int64_t zeros = 0x0;
                    memcpy(sendArp->arp_tha, &(zeros), 6);
                    
                    if (line[12] == '-') {
                        memcpy(sendArp->arp_tpa, &(destinationIp.s_addr), 4);
                    } else {
                        struct in_addr *arpDestination;
                        char arpDestinationStr[50];
                        strncpy(arpDestinationStr, line+12, 8);
                        
                        int ip = inet_addr(arpDestinationStr);
                        
                        memcpy(sendArp->arp_tpa, &(ip), 4);
                    }
                    
                    int arpSocket = 0; 
                    int arpSocketIndex = 0;
                    for (int z = 0; z <4; z++) {
                        if (strncmp(interface, addresses[z].interfaceName, 7) == 0) {
                            arpSocket = addresses[z].fileDescriptor;
                            arpSocketIndex = z;
                            break;
                        }
                    }
                    
                    send(arpSocket, arpRequest, 42, 0);
                    
                    char arpResponse[50];
                    int arpResponseSize = recv(arpSocket, arpResponse, 50, 0);

                    // Add MAC to original packet
                    struct ether_header *arpResponseStruct;
                    arpResponseStruct = (struct ether_header *)(arpResponse);
                    memcpy(ether->ether_shost, addresses[arpSocketIndex].mac, 6);
                    memcpy(ether->ether_dhost, arpResponseStruct->ether_shost, 6);

                    // Forward original packet
                    printf("Forwarding packet to %s\n", ether_ntoa((struct ether_addr *)ether->ether_dhost));
                    send(arpSocket, packet, packetSize, 0);
                }
            }
        }
        
        //what else to do is up to you, you can send packets with send,
        //just like we used for TCP sockets (or you can use sendto, but it
        //is not necessary, since the headers, including all addresses,
        //need to be in the buffer you are sending)
        
    }
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}


    #define _UAPI_LINUX_IP_H
    #define _DEFAULT_SOURCE
    #define __USE_MISC
    /* Standard libraries */
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h> 
    #include <unistd.h>
    /*Raw packet and IP/Ethernet layer requirements*/
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <sys/socket.h> 
    #include <net/ethernet.h>
    #include <net/if.h>
    #include <linux/if_packet.h>
    #include <linux/if_arp.h>
    #include <arpa/inet.h>
    /*Formatting requirements*/
    #include <inttypes.h>
    #include <stdint.h>
    #include <string.h>
    #include <linux/types.h>
    #include <asm/byteorder.h>
    #include <time.h>
    /*Handling operations*/
    #include <sys/ioctl.h>

    uint16_t calculate_ip_checksum(struct iphdr *ip_ptr) {
        
        int num_words = (ip_ptr->ihl * 4) / 2; 
        uint16_t *word_list = (uint16_t *)ip_ptr; 
      
        uint32_t sum = 0;
        
        for(int i = 0;i < num_words;i++) {
            sum += word_list[i];
        }

        
            
            while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
            }
            
            return (uint16_t)~sum;
    }

    
        uint16_t tcp_checksum(struct tcphdr *tcp_ptr, struct iphdr *ip_ptr) {
            /*Values for calculating TCP checksum*/
            uint32_t sum = 0;
            uint16_t checksum = 0;
            uint8_t fixed8 = 0;
            uint8_t psd_buffer[12];
            uint16_t iph_len = ip_ptr->ihl * 4;
            uint16_t tcph_len = tcp_ptr->doff * 4;
            uint16_t total_words[((12 + tcp_ptr->doff * 4) / 2)];

            uint16_t tcp_seg_len = ntohs(ip_ptr->tot_len) - iph_len - tcph_len;
            uint16_t tcp_seg_net = htons(tcp_seg_len);
            
            memcpy(&psd_buffer[0], &ip_ptr->saddr, sizeof(ip_ptr->saddr));
            memcpy(&psd_buffer[4], &ip_ptr->daddr, sizeof(ip_ptr->daddr));
            memcpy(&psd_buffer[8], &fixed8, sizeof(fixed8));
            memcpy(&psd_buffer[9], &ip_ptr->protocol, sizeof(ip_ptr->protocol));
            memcpy(&psd_buffer[10], &tcp_seg_net, sizeof(tcp_seg_net));
            uint16_t *cursor;
            cursor = (uint16_t *)psd_buffer;
            for (int i = 0;i < sizeof(psd_buffer) / 2;i++) {
                sum += ntohs(cursor[i]);
            }
            cursor = (uint16_t *)tcp_ptr;
            for (int i = 0;i < tcp_ptr->doff * 4 / 2;i++) {
                sum += ntohs(cursor[i]);
            }
            while (sum >> 16) { 
            sum = (sum >> 16) + (sum & 0xffff);
            }
            checksum = ~sum;
            return checksum;
        }
    int main()  {
    
        
        /*Defining values for our ETH/IP packets*/
        unsigned char srcmac[ETH_ALEN] = {0xff, 0xff,0xff, 0xff, 0xff, 0xff};
        unsigned char dstmac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t dscp_value = 22;
        uint8_t ecn = 0;
        uint16_t source_port = 32786 + (rand() % 28232);
        
        /*Struct definitions of our ETH, IP and TCP header*/
        struct sockaddr_ll rcv_device;
            memset(&rcv_device, 0, sizeof(rcv_device));
            rcv_device.sll_family = AF_PACKET;
            rcv_device.sll_protocol = htons(ETH_P_IP);
            rcv_device.sll_ifindex = if_nametoindex("eth0");
            rcv_device.sll_hatype = ARPHRD_ETHER;
            rcv_device.sll_pkttype = PACKET_OUTGOING;
            rcv_device.sll_halen = ETH_ALEN;
            memcpy(rcv_device.sll_addr, dstmac, 6);

        

        char FULL_FRAME[1500];
        struct ethhdr *eth_ptr = (struct ethhdr *) FULL_FRAME;
        struct iphdr *ip_ptr = (struct iphdr *) (FULL_FRAME + sizeof(struct ethhdr));
        struct tcphdr *tcp_ptr = (struct tcphdr *) (FULL_FRAME + sizeof(struct ethhdr) + sizeof(struct iphdr));
        //Ethernet Packet
        if (eth_ptr != NULL) {
        memcpy(eth_ptr->h_dest, &dstmac, ETH_ALEN);
        memcpy(eth_ptr->h_source, &dstmac, ETH_ALEN);
        eth_ptr->h_proto = htons(0x0800);
        }
        //IP Packet
        if (ip_ptr != NULL) {
        ip_ptr->ihl = 5;
        ip_ptr->version = 4;
        ip_ptr->tos = (dscp_value << 2) | ecn;
        ip_ptr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip_ptr->id = htons(0);
        ip_ptr->frag_off = htons(16384);
        ip_ptr->ttl = 64;
        ip_ptr->protocol = IPPROTO_TCP;
        ip_ptr->check = htons(0);
        ip_ptr->saddr = inet_addr("255.255.255.255");
        ip_ptr->daddr = inet_addr("255.255.255.255");
        }
        uint16_t ip_chksum = calculate_ip_checksum((struct iphdr *) &ip_ptr);
        ip_ptr->check = htons(ip_chksum);
        //TCP header
        ssize_t tcphdrsiz = sizeof(struct tcphdr);
        if (tcp_ptr != NULL) {
        tcp_ptr->source = htons(source_port);
        tcp_ptr->dest = htons(200);
        tcp_ptr->seq = htons(rand());
        tcp_ptr->doff = tcphdrsiz / 4; 
        tcp_ptr->fin = 0;
        tcp_ptr->syn = 0;
        tcp_ptr->rst = 1;
        tcp_ptr->psh = 0;
        tcp_ptr->ack = 0;
        tcp_ptr->urg = 0;
        tcp_ptr->res2 = 0;
        tcp_ptr->window = htons(5840);
        tcp_ptr->check = htons(0);
        }
        tcp_ptr->check = htons(tcp_checksum((struct tcphdr*) tcp_ptr, (struct iphdr*) ip_ptr));



        ssize_t FRAME_SIZE = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
        int sock_fd;
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (sock_fd == -1) {
            perror("socket");
            EXIT_FAILURE;
        }
        
        ssize_t bytes_sent = sendto(sock_fd, FULL_FRAME, FRAME_SIZE, 0, (struct sockaddr *) &rcv_device, sizeof(rcv_device));

        if (bytes_sent == -1) {
            perror("connection error");
            EXIT_FAILURE;
        }
        if (bytes_sent == 0) {
            perror("no bytes sent");
            EXIT_FAILURE;
        } else {
            printf("%i", bytes_sent);
        }
        

        return 0;
    }
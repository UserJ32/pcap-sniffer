#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>               // 패킷 캡처 라이브러리
#include <arpa/inet.h>          // IP주소를 문자열로 출력할 때 필요한 라이브러리

/* Ethernet Header */
struct ethheader {
    u_char ether_dhost[6];     // 목적지 MAC 주소
    u_char ether_shost[6];     // 출발지 MAC 주소
    u_short ether_type;        // 프로토콜 타입 (IP, ARP, RARP, etc)
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, // 헤더 길이
                       iph_ver:4; // IP 버전
    unsigned char      iph_tos; // 서비스 타입
    unsigned short int iph_len; //IP 패킷 길이 (data + header)
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl; // Time to Live
    unsigned char      iph_protocol; // 프로토콜 타입
    unsigned short int iph_chksum; // IP datagram checksum
    struct  in_addr    iph_sourceip; // 출발지 IP 주소
    struct  in_addr    iph_destip;   // 목적지지 IP 주소
  };

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* 출발지 port */
    u_short tcp_dport;               /* 목적지 port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷인지 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == 6) { // TCP 패킷인지 확인 (6 == TCP)

            // TCP 헤더 위치 계산
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

            // 이더넷 헤더 출력
            printf("Ethernet Header:\n");
            printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP 헤더 출력
            printf("IP Header:\n");
            printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            // TCP 포트 출력
            printf("TCP Header:\n");
            printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // 메시지(payload) 출력
            int ip_header_len = ip->iph_ihl * 4;               // IP 헤더 길이 계산
            int tcp_header_len = TH_OFF(tcp) * 4;              // TCP 헤더 길이 계산
            int header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int message_len = header->caplen - header_size;    // payload 길이 계산

            printf("Message: ");
            for (int i = 0; i < (message_len < 16 ? message_len : 16); i++) {
                printf("%02x ", packet[header_size + i]);     // 최대 16바이트 출력
            }
            printf("\n\n");
        }
    }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // tcp를 출력하도록 변경
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
//sender target
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close

#define ETHER_ADDR_LEN 6

struct	ether_header {
    u_int8_t    ether_dhost[ETHER_ADDR_LEN];
    u_int8_t    ether_shost[ETHER_ADDR_LEN];
    u_int16_t   ether_type;
};

struct arp_header {
    u_short arp_htype; /*hardware type*/
    u_short arp_p; /*protocol*/
    u_char arp_hsize; /*hardware size*/
    u_char arp_psize; /*protocol size*/
    u_short arp_opcode; /*opcode*/
    u_char arp_smhost[6]; /*sender mac address*/
    u_char arp_sip[4];
    u_char arp_dmhost[6]; /*target mac address*/
    u_char arp_dip[4];

};



void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

unsigned char* macMac(unsigned char *dev){
    int fd;
    unsigned char *mac;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
            mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    }

    close(fd);

    return mac;
}



int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  struct ether_header sender_eth;
  struct arp_header sender_arph;

  struct ether_header *get_eth;
  struct arp_header *get_arph;

  struct ether_header target_eth;
  struct arp_header target_arph;


  char* dev = argv[1];
  unsigned char* S_MAC;
  char errbuf[PCAP_ERRBUF_SIZE];

  unsigned char packet_t[100] = { 0, };
  unsigned char packet2[100] = { 0, };

  S_MAC = macMac(dev);

  sender_eth.ether_dhost[0] = 0xff;
  sender_eth.ether_dhost[1] = 0xff;
  sender_eth.ether_dhost[2] = 0xff;
  sender_eth.ether_dhost[3] = 0xff;
  sender_eth.ether_dhost[4] = 0xff;
  sender_eth.ether_dhost[5] = 0xff;

  sender_eth.ether_shost[0] = S_MAC[0];
  sender_eth.ether_shost[1] = S_MAC[1];
  sender_eth.ether_shost[2] = S_MAC[2];
  sender_eth.ether_shost[3] = S_MAC[3];
  sender_eth.ether_shost[4] = S_MAC[4];
  sender_eth.ether_shost[5] = S_MAC[5];

  sender_eth.ether_type = 0x0608;

  sender_arph.arp_htype = 0x0100;
  sender_arph.arp_p = 0x0008;
  sender_arph.arp_hsize = 0x06;
  sender_arph.arp_psize = 0x04;
  sender_arph.arp_opcode = 0x0100;
  sender_arph.arp_smhost[0] = S_MAC[0];
  sender_arph.arp_smhost[1] = S_MAC[1];
  sender_arph.arp_smhost[2] = S_MAC[2];
  sender_arph.arp_smhost[3] = S_MAC[3];
  sender_arph.arp_smhost[4] = S_MAC[4];
  sender_arph.arp_smhost[5] = S_MAC[5];
  sscanf(argv[2], "%d.%d.%d.%d", &sender_arph.arp_sip[0], &sender_arph.arp_sip[1], &sender_arph.arp_sip[2], &sender_arph.arp_sip[3]);
  sender_arph.arp_dmhost[0] = 0x00;
  sender_arph.arp_dmhost[1] = 0x00;
  sender_arph.arp_dmhost[2] = 0x00;
  sender_arph.arp_dmhost[3] = 0x00;
  sender_arph.arp_dmhost[4] = 0x00;
  sender_arph.arp_dmhost[5] = 0x00;
  sscanf(argv[3], "%d.%d.%d.%d", &sender_arph.arp_dip[0], &sender_arph.arp_dip[1], &sender_arph.arp_dip[2], &sender_arph.arp_dip[3]);



  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  memcpy(packet_t, &sender_eth, sizeof(sender_eth));
  memcpy(packet_t + sizeof(sender_eth), &sender_arph, sizeof(sender_arph));

  for(int i = 42; i< 60; i++){
      packet_t[i] = 0;
  }


  //pcap_sendpacket(handle, packet_t, 60);

  for(int i = 0; i< 2; i++){
    struct pcap_pkthdr* header;
    const u_char* packet;
    pcap_sendpacket(handle, packet_t, 60);
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    get_eth = (struct ether_header *)packet;
    get_arph = (struct arp_header *)(packet + sizeof(struct ether_header));

    memcpy(&packet2, packet + 6, 6);
    memcpy(&packet2[6], packet, 6);
    memcpy(&packet2[12], packet + 12, 8);
    packet2[20] = 0x00;
    packet2[21] = 0x02;
    memcpy(&packet2[22], packet + 32, 10);
    memcpy(&packet2[32], packet + 22, 10);
    packet2[31] = 0x01;

    for(int j = 0 ; j< 42 ; j++){
        printf("%02x ", packet2[j]);
    }
    printf("\n");

    pcap_sendpacket(handle, packet2, 42);


   }

  pcap_close(handle);

  return 0;

}

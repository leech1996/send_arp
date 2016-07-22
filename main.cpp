#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "arp.h"

int main(int argc, char* argv[])
{
    // my ip address

    FILE *f;
    char *command="ifconfig | grep -o '[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}'";
    f=popen(command,"r");
    if(f==NULL){
        printf("popen error\n");
        return -1;
    }
    char *myip=(char*)malloc(50);
    fgets(myip, 50, f);
    pclose(f);

    // my mac address

    command="ifconfig | grep -o '..:..:..:..:..:..'";
    f=popen(command,"r");
    if(f==NULL){
        printf("popen error\n");
        return -1;
    }
    char *mymac=(char*)malloc(50);
    fgets(mymac, 50, f);
    pclose(f);

    // gateway ip address

    char *gateip=(char*)malloc(50);
    command="route -n | grep ens33 | grep 'UG[ \\t]' | awk '{print $2}'";
    f=popen(command,"r");
    if(f==NULL){
        printf("popen error\n");
        return -1;
    }
    fgets(gateip,50,f);
    pclose(f);
    printf("%s%s%s",myip,mymac,gateip);
}
/*




    char * dev;
    char * net;
    char * mask;

    char errbuf[PCAP_ERRBUF_SIZE]={0,};

    // getting network device name

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("device : %s\n",dev);

    int ret;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    // getting network and mask information from device name.

    ret=pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if(ret==-1){
        printf("%s\n", errbuf);
        exit(1);
    }

    struct in_addr net_addr;

    net_addr.s_addr = netp;     // netp(bpf_u_int32) => net_addr.s_addr(u_int32_t)

    net = inet_ntoa(net_addr);  // net_addr(in_addr structure) => string (network address)

    if(net == NULL)
    {
        perror("No Network Address");
        exit(1);
    }

    printf("NET: %s\n",net);

    struct in_addr mask_addr;

    mask_addr.s_addr = maskp;   // maskp(bpf_u_int32) => mask_addr.s_addr(u_int32_t)

    mask=inet_ntoa(mask_addr);  // mask_addr(in_addr structure) => string (subnet mask address)

    if(mask == NULL)
    {
        perror("No Subnet Mask Address");
        exit(1);
    }

    printf("%s\n",mask);

    int fd;
    struct ifreq ifr;

    unsigned char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    //display mac address
    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    unsigned char *ipaddr;

    ioctl(fd, SIOCGIFADDR, &ifr);
    ipaddr = (unsigned char*)ifr.ifr_addr.sa_data;
    for (int i=2;i<6;i++){
        printf("%d",ipaddr[i]);
    }
    system("route>route.txt");

    FILE *f;

    f= fopen("route.txt","r");

    fseek(f, 0, SEEK_END);

    int filesize=ftell(f);

    fseek(f, 0, SEEK_SET);

    char buffer[5000]={0,};

    fread(buffer, sizeof(char), filesize, f);

    printf("%s\n",buffer);

    const char *pattern="/\b(?:\d{1,3}\.){3}\d{1,3}\b/g";
    // /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
    printf("s\n",pattern);
    regex_t reg;
    regmatch_t matches[20];
    int result;
    result = regcomp( &reg, pattern, REG_EXTENDED ); //패턴을 컴파일

    if( regexec( &reg, buffer, 20, matches, 0 ) == 0 ){
        // 패턴이 일치할 경우 처리할 명령
        // 이 때 데이터 사용 방법은 아래와 같다.(패턴이 1부터 시작하는 걸로 기억한다)
        // matches[1].rm_so : 패턴이 발견된 시작 위치
        // matches[1].rm_eo: 해당 패턴이 끝나는 위치
        // strncpy() 등을 통해 복사할 때 길이는 'matches[1].rm_eo-matches[1].rm_so' 로 계산해주면 된다.
    }

    regfree( &reg ); // 컴파일한 결과를 해제 함
    return 0;

    struct iphdr *ipp;

    struct arphdr *arpp;
}
*/

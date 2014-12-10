#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#pragma pack(1)  //��һ���ֽ��ڴ����
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255

char *iptos(u_long in);       //u_long��Ϊ unsigned long
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);   
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *local_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
DWORD WINAPI RouteThread(LPVOID lpParameter);
//IP��ַ��ʽ
struct IpAddress
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

//֡ͷ���ṹ�壬��14�ֽ�
struct EthernetHeader
{
    u_char DestMAC[6];    //Ŀ��MAC��ַ 6�ֽ�
    u_char SourMAC[6];   //ԴMAC��ַ 6�ֽ�
    u_short EthType;         //��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp  2�ֽ�
};

//IPͷ���ṹ�壬��20�ֽ�
struct IpHeader
{
    unsigned char Version_HLen;   //�汾��Ϣ4λ ��ͷ����4λ 1�ֽ�
    unsigned char TOS;                    //��������    1�ֽ�
    short Length;                              //���ݰ����� 2�ֽ�
    short Ident;                                 //���ݰ���ʶ  2�ֽ�
    short Flags_Offset;                    //��־3λ��Ƭƫ��13λ  2�ֽ�
    unsigned char TTL;                   //���ʱ��  1�ֽ�
    unsigned char Protocol;          //Э������  1�ֽ�
    short Checksum;                       //�ײ�У��� 2�ֽ�
	IpAddress SourceAddr;       //ԴIP��ַ   4�ֽ�
	IpAddress DestinationAddr; //Ŀ��IP��ַ  4�ֽ�
};

//TCPͷ���ṹ�壬��20�ֽ�
struct TcpHeader
{
    unsigned short SrcPort;                        //Դ�˿ں�  2�ֽ�
    unsigned short DstPort;                        //Ŀ�Ķ˿ں� 2�ֽ�
    unsigned int SequenceNum;               //���  4�ֽ�
    unsigned int Acknowledgment;         //ȷ�Ϻ�  4�ֽ�
    unsigned char HdrLen;                         //�ײ�����4λ������λ6λ ��10λ
    unsigned char Flags;                              //��־λ6λ
    unsigned short AdvertisedWindow;  //���ڴ�С16λ 2�ֽ�
    unsigned short Checksum;                  //У���16λ   2�ֽ�
    unsigned short UrgPtr;						  //����ָ��16λ   2�ֽ�
};

//TCPα�ײ��ṹ�� 12�ֽ�
struct PsdTcpHeader
{
	IpAddress SourceAddr;                     //ԴIP��ַ  4�ֽ�
	IpAddress DestinationAddr;             //Ŀ��IP��ַ 4�ֽ�
    char Zero;                                                    //���λ  1�ֽ�
    char Protcol;                                               //Э���  1�ֽ�
    unsigned short TcpLen;                           //TCP������ 2�ֽ�
};

//28�ֽ�ARP֡�ṹ
struct Arpheader {
	unsigned short HardwareType; //Ӳ������
	unsigned short ProtocolType; //Э������
	unsigned char HardwareAddLen; //Ӳ����ַ����
	unsigned char ProtocolAddLen; //Э���ַ����
	unsigned short OperationField; //�����ֶ�
	unsigned char SourceMacAdd[6]; //Դmac��ַ
	unsigned long SourceIpAdd; //Դip��ַ
	unsigned char DestMacAdd[6]; //Ŀ��mac��ַ
	unsigned long DestIpAdd; //Ŀ��ip��ַ
};

//arp���ṹ
struct ArpPacket {
	EthernetHeader ed;
	Arpheader ah;
};

struct sparam {
	pcap_t *adhandle;
	char *ip;
	unsigned char *mac;
	char *netmask;
};
struct gparam {
	pcap_t *adhandle;
};
struct rparam{
	pcap_t *adhandle_rec;
	pcap_t *adhandle_send;
	pcap_if_t  * alldevs;       //��������������
};

struct ip_mac_list{
	IpAddress ip;
	unsigned char mac[6];
};
int con = 0;
bool flag;
bool sentOnce = false;            //�����Ƿ��Ѿ����ٷ��͹�һ��
HANDLE routethread;     //ת�����ݵ��߳�
unsigned char *local_mac;          //����MAC��ַ
struct sparam sp;
struct gparam gp;
struct rparam rp;
ip_mac_list  list[256];                       //�洢IP��MAC��ַ�Ķ�Ӧ��
//���У��͵ķ���
unsigned short checksum(unsigned short *data, int length)
{
    unsigned long temp = 0;
    while (length > 1)
    {
        temp +=  *data++;
        length -= sizeof(unsigned short);
    }
    if (length)
    {
        temp += *(unsigned short*)data;
    }
    temp = (temp >> 16) + (temp &0xffff);
    temp += (temp >> 16);
    return (unsigned short)(~temp);
}


int main(){

	struct EthernetHeader ethernet;    //��̫��֡ͷ
    struct IpHeader ip;                            //IPͷ
    struct TcpHeader tcp;                      //TCPͷ
    struct PsdTcpHeader ptcp;             //TCPα�ײ�
	char *ip_addr;                                    //IP��ַ
	char *ip_netmask;                             //��������
	char *route_mac;                          //�м�·�ɵ�MAC��ַ
	unsigned char SendBuffer[200];       //���Ͷ���
	char TcpData[80];   //��������
	pcap_if_t  * alldevs;                //��������������
	pcap_if_t  *d,*d2;					//ѡ�е�����������
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	pcap_t *adhandle,*adhandle2;           //��׽ʵ��,��pcap_open���صĶ���,adhandle�������������ݣ�adhandle2��������������
	int i = 0;                            //��������������
	HANDLE sendthread;      //����ARP���߳�
	HANDLE recvthread;       //����ARP���߳�

	ip_addr = (char *) malloc(sizeof(char) * 16); //�����ڴ���IP��ַ
	if (ip_addr == NULL)
	{
		printf("�����ڴ���IP��ַʧ��!\n");
		return -1;
	}
	ip_netmask = (char *) malloc(sizeof(char) * 16); //�����ڴ���NETMASK��ַ
	if (ip_netmask == NULL)
	{
		printf("�����ڴ���NETMASK��ַʧ��!\n");
		return -1;
	}
	local_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //�����ڴ���MAC��ַ
	if (local_mac == NULL)
	{
		printf("�����ڴ���MAC��ַʧ��!\n");
		return -1;
	}
	route_mac = (char *) malloc(sizeof(char) *17); //�����ڴ����м�·�ɵ�MAC��ַ
	if (route_mac == NULL)
	{
		printf("�����ڴ����м�·��MAC��ַʧ��!\n");
		return -1;
	}
	//��ȡ�����������б�
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//���Ϊ-1������ֻ�ȡ�������б�ʧ��
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)���������˳�,exit(other)Ϊ�������˳�,���ֵ�ᴫ������ϵͳ
		exit(1);
	}

	for(d = alldevs;d !=NULL;d = d->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d->name);
		if(d->description){
			//��ӡ��������������Ϣ
			printf("description:%s\n",d->description);
		}else{
			//������������������Ϣ
			printf("description:%s","no description\n");
		}

		 pcap_addr_t *a;       //�����������ĵ�ַ�����洢����
		 for(a = d->addresses;a;a = a->next){
			 //sa_family�����˵�ַ������,��IPV4��ַ���ͻ���IPV6��ַ����
			 switch (a->addr->sa_family)
			 {
				 case AF_INET:  //����IPV4���͵�ַ
					 printf("Address Family Name:AF_INET\n");
					 if(a->addr){
						 //->�����ȼ���ͬ������,����ǿ������ת��,��ΪaddrΪsockaddr���ͣ�������в�����ת��Ϊsockaddr_in����
						 printf("Address:%s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
					 }
					if (a->netmask){
						 printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
					}
					if (a->broadaddr){
						   printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
					 }
					 if (a->dstaddr){
						   printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
					 }
        			 break;
				 case AF_INET6: //����IPV6���͵�ַ
					 printf("Address Family Name:AF_INET6\n");
					 printf("this is an IPV6 address\n");
					 break;
				 default:
					 break;
			 }
		 }
	}
	//iΪ0��������ѭ��δ����,��û���ҵ�������,���ܵ�ԭ��ΪWinpcapû�а�װ����δɨ�赽
	if(i == 0){
		printf("interface not found,please check winpcap installation");
	}

	int num;
	printf("��������Ҫת�����ݵ���������:");

	scanf_s("%d",&num);

	//��ת��ѡ�е�������
	for(d=alldevs, i=0; i< num-1 ; d=d->next, i++);

	//���е��˴�˵���û��������ǺϷ��ģ��ҵ�������������
	if((adhandle = pcap_open(d->name,		//�豸����
													65535,       //������ݰ������ݳ���
													PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ
													1000,           //��ʱʱ��
													NULL,          //Զ����֤
													errbuf         //���󻺳�
													)) == NULL){
    //��������ʧ��,��ӡ�����ͷ��������б�
	fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    // �ͷ��豸�б� 
    pcap_freealldevs(alldevs);
    return -1;
	}

	int num2;
	printf("��������Ҫ�������ݵ���������:");

	scanf_s("%d",&num2);
	//�û���������ֳ�������Χ


	//��ת��ѡ�е�������
	for(d2=alldevs, i=0; i< num2-1 ; d2=d2->next, i++);

	//���е��˴�˵���û��������ǺϷ���
	if((adhandle2 = pcap_open(d2->name,		//�豸����
													65535,       //������ݰ������ݳ���
													PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ
													1000,           //��ʱʱ��
													NULL,          //Զ����֤
													errbuf         //���󻺳�
													)) == NULL){
    //��������ʧ��,��ӡ�����ͷ��������б�
	fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d2->name);
    // �ͷ��豸�б� 
    pcap_freealldevs(alldevs);
    return -1;
	}


	//���е��˴�˵�����Դ򿪸��豸������adhandle�Ѿ��õ���Ч��ֵ��
	//����ѡ�е�������,�����洢ip������ı���
	ifget(d, ip_addr, ip_netmask); //��ȡ��ѡ�����Ļ�����Ϣ--����--IP��ַ
	GetSelfMac(adhandle, ip_addr, local_mac); //���������豸��������豸ip��ַ��ȡ���豸��MAC��ַ
	sp.adhandle = adhandle;
	sp.ip = ip_addr;
	sp.mac = local_mac;
	sp.netmask = ip_netmask;
	gp.adhandle = adhandle;
	rp.adhandle_send = adhandle;
	rp.adhandle_rec = adhandle2;
	rp.alldevs = alldevs;
	sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
			&sp, 0, NULL);
	recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
			0, NULL);
	//�ͷ������������б�
	pcap_freealldevs(alldevs);

	system("pause");
	return 0;

}

/* ���������͵�IP��ַת�����ַ������͵� */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/* ��ȡ������Ϣ*/
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask) {
	pcap_addr_t *a;
	//�������еĵ�ַ,a����һ��pcap_addr
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family) {
		case AF_INET:  //sa_family ����2�ֽڵĵ�ַ���壬һ�㶼�ǡ�AF_xxx������ʽ��ͨ���õĶ���AF_INET������IPV4
			if (a->addr) {
				char *ipstr;
				//����ַת��Ϊ�ַ���
				ipstr = iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr); //*ip_addr
				printf("ipstr:%s\n",ipstr);
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask) {
				char *netmaskstr;
				netmaskstr = iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
				printf("netmask:%s\n",netmaskstr);
				memcpy(ip_netmask, netmaskstr, 16);
			}
		case AF_INET6:
			break;
		}
	}
}

/* ��ȡ�Լ�������MAC��ַ */
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *local_mac) {
	unsigned char sendbuf[42]; //arp���ṹ��С
	int i = -1;
	int res;
	EthernetHeader eh; //��̫��֡ͷ
	Arpheader ah;  //ARP֡ͷ
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	//���ѿ����ڴ�ռ� eh.dest_mac_add ���� 6���ֽڵ�ֵ��Ϊֵ 0xff��
	memset(eh.DestMAC, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
	memset(eh.SourMAC, 0x0f, 6);
	memset(ah.DestMacAdd, 0x0f, 6);
	memset(ah.SourceMacAdd, 0x00, 6);
	//htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��
	eh.EthType = htons(ETH_ARP);
	ah.HardwareType= htons(ARP_HARDWARE);
	ah.ProtocolType = htons(ETH_IP);
	ah.HardwareAddLen = 6;
	ah.ProtocolAddLen = 4;
	ah.SourceIpAdd = inet_addr("100.100.100.100"); //����������ip
	ah.OperationField = htons(ARP_REQUEST);
	ah.DestIpAdd = inet_addr(ip_addr);
	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nARP�����ͳɹ�,������ȡ������MAC��ַ\n");
	} else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;
	}
	//��interface�����߼�¼�ļ���ȡһ������
	//pcap_next_ex(pcap_t* p,struct pcap_pkthdr** pkt_header,const u_char** pkt_data)
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)
				&& *(unsigned short*) (pkt_data + 20) == htons(ARP_REPLY)
				&& *(unsigned long*) (pkt_data + 38)
						== inet_addr("100.100.100.100")) {
			for (i = 0; i < 6; i++) {
				local_mac[i] = *(unsigned char *) (pkt_data + 22 + i);
			}
			printf("��ȡ�Լ�������MAC��ַ�ɹ�!\n");
			break;
		}
	}
	if (i == 6) {
		return 1;
	} else {
		return 0;
	}
}
/* ������������п��ܵ�IP��ַ����ARP������߳� */
DWORD WINAPI SendArpPacket(LPVOID lpParameter) //(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
	sparam *spara = (sparam *) lpParameter;
	pcap_t *adhandle = spara->adhandle;
	char *ip = spara->ip;
	unsigned char *mac = spara->mac;
	char *netmask = spara->netmask;
	printf("local_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	printf("�����IP��ַΪ:%s\n", ip);
	printf("��ַ����NETMASKΪ:%s\n", netmask);
	printf("\n");
	unsigned char sendbuf[42]; //arp���ṹ��С
	EthernetHeader eh;
	Arpheader ah;
	memset(eh.DestMAC, 0xff, 6);       //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
	memcpy(eh.SourMAC, mac, 6);
	memcpy(ah.SourceMacAdd, mac, 6);
	memset(ah.DestMacAdd, 0x00, 6);
	eh.EthType = htons(ETH_ARP);
	ah.HardwareType = htons(ARP_HARDWARE);
	ah.ProtocolType = htons(ETH_IP);
	ah.HardwareAddLen = 6;
	ah.ProtocolAddLen = 4;
	ah.SourceIpAdd = inet_addr(ip); //���󷽵�IP��ַΪ�����IP��ַ
	ah.OperationField = htons(ARP_REQUEST);
	//��������ڹ㲥����arp��
	unsigned long myip = inet_addr(ip);
	unsigned long mynetmask = inet_addr(netmask);
	unsigned long hisip = htonl((myip & mynetmask));
	for (int i = 0; i < HOSTNUM; i++) {
		ah.DestIpAdd = htonl(hisip + i);
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &eh, sizeof(eh));
		memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
		if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
			//printf("\nPacketSend succeed\n");
		} else {
			printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		}
		Sleep(50);
	}
	Sleep(1000);
	flag = TRUE;
	return 0;
}
/* �������������ݰ���ȡ�������IP��ַ */
DWORD WINAPI GetLivePC(LPVOID lpParameter) //(pcap_t *adhandle)
{
	gparam *gpara = (gparam *) lpParameter;
	pcap_t *adhandle = gpara->adhandle;
	int res;
	unsigned char Mac[6];
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	while (true) {
		if (flag) {
			printf("��ȡMAC��ַ���\n");
			routethread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) RouteThread, &rp,
			0, NULL);
			break;
		}
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
			if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)) {
				ArpPacket *recv = (ArpPacket *) pkt_data;
				if (*(unsigned short *) (pkt_data + 20) == htons(ARP_REPLY)) {
					printf("-------------------------------------------\n");
					printf("IP��ַ:%d.%d.%d.%d   MAC��ַ:",
						     recv->ah.SourceIpAdd & 255,
							 recv->ah.SourceIpAdd >> 8 & 255,
							 recv->ah.SourceIpAdd >> 16 & 255,
							 recv->ah.SourceIpAdd >> 24 & 255);
							list[con].ip.byte1 = recv->ah.SourceIpAdd & 255;
							list[con].ip.byte2 = recv->ah.SourceIpAdd >> 8& 255;
							list[con].ip.byte3 = recv->ah.SourceIpAdd >> 16& 255;
							list[con].ip.byte4 = recv->ah.SourceIpAdd >> 24& 255;
					for (int i = 0; i < 6; i++) {
						Mac[i] = *(unsigned char *) (pkt_data + 22 + i);
						list[con].mac[i] =  Mac[i];
						printf("%02x", Mac[i]);
							if(i<5)
								printf("-");
					}
					con++;
					printf("  ����:%d\n",con);
					printf("\n");
				}
			}
		}
		Sleep(10);
	}
	return 0;
}

DWORD WINAPI RouteThread(LPVOID lpParameter){

	rparam *rpara = (rparam *) lpParameter;
	struct bpf_program fcode; 
	u_int netmask;       
	int res;              
	char packet_filter[] = "tcp";
	struct pcap_pkthdr *header;    //���յ������ݰ���ͷ��
    const u_char *pkt_data;			  //���յ������ݰ�������
	EthernetHeader *ethernet;    //��̫��֡ͷ
    IpHeader *ip;                            //IPͷ
    TcpHeader *tcp;               
	unsigned char *sou_mac;      //ԴMAC
	unsigned char *des_mac;      //Ŀ��MAC
	u_int ip_len;  
	pcap_if_t *alldevs;
	pcap_t *adhandle,*adhandle2;
	alldevs = rpara->alldevs;
	adhandle = rpara->adhandle_send;
	adhandle2 = rpara->adhandle_rec;
	unsigned char SendBuffer[2000];       //���Ͷ���
	char * data;
	//��ӡ���,���ڼ�����
	struct EthernetHeader send_ethernet;    //��̫��֡ͷ
	struct IpHeader send_ip;                            //IPͷ
    struct TcpHeader send_tcp;                      //TCPͷ
	struct PsdTcpHeader send_ptcp;                //α�ײ�
	//ΪԴMAC��ַ���ٵ�ַ�ռ�
	sou_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //�����ڴ���MAC��ַ
	if (sou_mac == NULL)
	{
		printf("������ԴMAC��ַʧ��!\n");
		return -1;
	}
	//ΪĿ��IP���ٵ�ַ�ռ�
	des_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //�����ڴ���MAC��ַ
	if (des_mac == NULL)
	{
		printf("������Ŀ��MAC��ַʧ��!\n");
		return -1;
	}

        netmask=0xffffff;

	if(pcap_compile(adhandle2,	//�������������
										&fcode,
										packet_filter,   //����ip��UDP
										1,                       //�Ż���־
										netmask           //��������
										)<0)
	{
		//���˳�������
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        // �ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
	}

	//���ù�����
    if (pcap_setfilter(adhandle2, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        //�ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
    }

	//����pcap_next_ex���������ݰ�
	while((res = pcap_next_ex(adhandle2,&header,&pkt_data))>=0)
	{
		if(res ==0){
			//����ֵΪ0����������ݰ���ʱ������ѭ����������
			continue;
		}else{
			printf("�յ���������!!!\n");
			printf("-----------------------------------------------------------\n");
			//���е��˴�������ܵ����������ݰ�
			ethernet =  (EthernetHeader *)(pkt_data);
			for(int i=0;i<6;i++){
				sou_mac[i] = ethernet->SourMAC[i];
			}
			for(int i=0;i<6;i++){
				des_mac[i] = ethernet->DestMAC[i];
			}
			// ���IP���ݰ�ͷ����λ��
			ip = (IpHeader *) (pkt_data +14);    //14Ϊ��̫��֡ͷ������
			//���TCPͷ����λ��
			ip_len = (ip->Version_HLen & 0xf) *4;
			tcp = (TcpHeader *)((u_char *)ip+ip_len);
			data = (char *)((u_char *)tcp+20);
			printf("����:%s\n",data);
			printf("ԴIP: %d.%d.%d.%d -> Ŀ��IP: %d.%d.%d.%d\n",
					ip->SourceAddr.byte1,
					ip->SourceAddr.byte2,
					ip->SourceAddr.byte3,
					ip->SourceAddr.byte4,
				    ip->DestinationAddr.byte1,
				    ip->DestinationAddr.byte2,
				    ip->DestinationAddr.byte3,
				    ip->DestinationAddr.byte4);
			 printf("ԴMAC��ַ:%02x-%02x-%02x-%02x-%02x-%02x\n", sou_mac[0], sou_mac[1], sou_mac[2],
			    sou_mac[3], sou_mac[4], sou_mac[5]);
			printf("Ŀ��MAC��ַ:%02x-%02x-%02x-%02x-%02x-%02x\n", des_mac[0], des_mac[1], des_mac[2],
			    des_mac[3], des_mac[4], des_mac[5]);
		}
		//���¿�ʼ����֡����
		//�����ж�data���ֵС��1500
		if(strlen(data)<1500){
			//Ŀ��MAC
			BYTE send_destmac[6];
			bool findMac = false;
			for(int c = 0;c<con;c++){
				if(ip->DestinationAddr.byte1 ==  list[c].ip.byte1&&
					ip->DestinationAddr.byte2 == list[c].ip.byte2&&
					ip->DestinationAddr.byte3 == list[c].ip.byte3&&
					ip->DestinationAddr.byte4 == list[c].ip.byte4)
				{
					printf("�ھ��������ҵ�������MAC!\n");
					findMac = true;
					send_destmac[0] = list[c].mac[0];   
					send_destmac[1] = list[c].mac[1];
					send_destmac[2] = list[c].mac[2];
					send_destmac[3] = list[c].mac[3];
					send_destmac[4] = list[c].mac[4];
					send_destmac[5] = list[c].mac[5];
				}
			}
			if(!findMac){
				send_destmac[0] = 0xff;   
				send_destmac[1] = 0xff;   
				send_destmac[2] = 0xff;   
				send_destmac[3] = 0xff;   
				send_destmac[4] = 0xff;   
				send_destmac[5] = 0xff;   
			}
			printf("�¹�����֡:\n");
			printf("Ŀ��MAC :%02x-%02x-%02x-%02x-%02x-%02x\n",
				send_destmac[0],send_destmac[1],send_destmac[2],
				send_destmac[3],send_destmac[4],send_destmac[5]
				);
			memcpy(send_ethernet.DestMAC, send_destmac, 6);
			//ԴMAC��ַ
			BYTE send_hostmac[6];
			//ԴMAC��ַ
			send_hostmac[0] = local_mac[0];     //��ֵ����MAC��ַ
			send_hostmac[1] = local_mac[1];
			send_hostmac[2] = local_mac[2];
			send_hostmac[3] = local_mac[3];
			send_hostmac[4] = local_mac[4];
			send_hostmac[5] = local_mac[5];
			printf("ԴMAC :%02x-%02x-%02x-%02x-%02x-%02x\n",
				send_hostmac[0],send_hostmac[1],send_hostmac[2],
				send_hostmac[3],send_hostmac[4],send_hostmac[5]
				);
			printf("ԴIP: %d.%d.%d.%d -> Ŀ��IP: %d.%d.%d.%d\n",
					ip->SourceAddr.byte1,
					ip->SourceAddr.byte2,
					ip->SourceAddr.byte3,
					ip->SourceAddr.byte4,
				    ip->DestinationAddr.byte1,
				    ip->DestinationAddr.byte2,
				    ip->DestinationAddr.byte3,
				    ip->DestinationAddr.byte4);
			//��ֵԴMAC��ַ
			memcpy(send_ethernet.SourMAC, send_hostmac, 6);
			send_ethernet.EthType = htons(0x0800);
			//��ֵSendBuffer
			memcpy(&SendBuffer, &send_ethernet, sizeof(struct EthernetHeader));
			//��ֵIPͷ����Ϣ
			send_ip.Version_HLen = 0x45;
			send_ip.TOS = 0;
			send_ip.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(data));
			send_ip.Ident = htons(1);
			send_ip.Flags_Offset = 0;
			send_ip.TTL = 128;
			send_ip.Protocol = 6;
			send_ip.Checksum = 0;
			send_ip.DestinationAddr.byte1 = ip->DestinationAddr.byte1;
			send_ip.DestinationAddr.byte2 = ip->DestinationAddr.byte2;
			send_ip.DestinationAddr.byte3 = ip->DestinationAddr.byte3;
			send_ip.DestinationAddr.byte4 = ip->DestinationAddr.byte4;
			send_ip.SourceAddr.byte1 = ip->SourceAddr.byte1;
			send_ip.SourceAddr.byte2 = ip->SourceAddr.byte2;
			send_ip.SourceAddr.byte3 = ip->SourceAddr.byte3;
			send_ip.SourceAddr.byte4 = ip->SourceAddr.byte4;
			memcpy(&SendBuffer[sizeof(struct EthernetHeader)], &send_ip, 20);
			//��ֵTCPͷ������
			send_tcp.DstPort = htons(102);
			send_tcp.SrcPort = htons(1000);
			send_tcp.SequenceNum = htonl(11);
			send_tcp.Acknowledgment = 0;
			send_tcp.HdrLen = 0x50;
			send_tcp.Flags = 0x18;
			send_tcp.AdvertisedWindow = htons(512);
			send_tcp.UrgPtr = 0;
			send_tcp.Checksum = 0;
			//��ֵSendBuffer
			memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &send_tcp, 20);
			//��ֵα�ײ�
			send_ptcp.SourceAddr = send_ip.SourceAddr;
			send_ptcp.DestinationAddr = send_ip.DestinationAddr;
			send_ptcp.Zero = 0;
			send_ptcp.Protcol = 6;
			send_ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(data));
			//������ʱ�洢��������������У���
			char TempBuffer[65535];
			memcpy(TempBuffer, &send_ptcp, sizeof(struct PsdTcpHeader));
			memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &send_tcp, sizeof(struct TcpHeader));
			memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), data, strlen(data));
			//����TCP��У���
			send_tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(data));
			//���°�SendBuffer��ֵ����Ϊ��ʱУ����Ѿ��ı䣬��ֵ�µ�
			memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &send_tcp, sizeof(struct TcpHeader));
			memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), data, strlen(data));
			//��ʼ��TempBufferΪ0���У��洢����������IPУ���
			memset(TempBuffer, 0, sizeof(TempBuffer));
			memcpy(TempBuffer, &send_ip, sizeof(struct IpHeader));
			//����IPУ���
			send_ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
			//���°�SendBuffer��ֵ��IPУ����Ѿ��ı�
			memcpy(SendBuffer + sizeof(struct EthernetHeader), &send_ip, sizeof(struct IpHeader));
			//�������еĳ���
			int size = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(data);
			int result = pcap_sendpacket(adhandle, SendBuffer,size);   //��adhandle����
			if (result != 0)
			{
				printf("Send Error!\n");
			} 
			else
			{   
				printf("���ͳɹ�!\n");
			}
		}

	}//while

}
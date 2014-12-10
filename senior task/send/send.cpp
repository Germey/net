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
struct ip_mac_list{
	IpAddress ip;
	unsigned char mac[6];
};
int con = 0;
bool flag;
bool sentOnce = false;            //�����Ƿ��Ѿ����ٷ��͹�һ��
struct sparam sp;
struct gparam gp;
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
	unsigned char *local_mac;          //����MAC��ַ
	char *route_mac;                          //�м�·�ɵ�MAC��ַ
	unsigned char SendBuffer[200];       //���Ͷ���
	char TcpData[80];   //��������
	pcap_if_t  * alldevs;       //��������������
	pcap_if_t  *d;					//ѡ�е�����������
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	pcap_t *adhandle;           //��׽ʵ��,��pcap_open���صĶ���
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
		//��ӡ���ػ��ص�ַ
		 printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
		 /**
		 pcap_addr *  next     ָ����һ����ַ��ָ��
		 sockaddr *  addr       IP��ַ
		 sockaddr *  netmask  ��������
		 sockaddr *  broadaddr   �㲥��ַ
		 sockaddr *  dstaddr        Ŀ�ĵ�ַ
		 */
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
	printf("������Ҫ�򿪵���������(1-%d):",i);
	//���û�ѡ��ѡ���ĸ�����������ץ��
	scanf_s("%d",&num);
	printf("\n");

	//�û���������ֳ�������Χ
	if(num<1||num>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ת��ѡ�е�������
	for(d=alldevs, i=0; i< num-1 ; d=d->next, i++);

	//���е��˴�˵���û��������ǺϷ���
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

	//���е��˴�˵�����Դ򿪸��豸������adhandle�Ѿ��õ���Ч��ֵ��
	//����ѡ�е�������,�����洢ip������ı���
	ifget(d, ip_addr, ip_netmask); //��ȡ��ѡ�����Ļ�����Ϣ--����--IP��ַ
	GetSelfMac(adhandle, ip_addr, local_mac); //���������豸��������豸ip��ַ��ȡ���豸��MAC��ַ
	sp.adhandle = adhandle;
	sp.ip = ip_addr;
	sp.mac = local_mac;
	sp.netmask = ip_netmask;
	gp.adhandle = adhandle;
	sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
			&sp, 0, NULL);
	recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
			0, NULL);
	printf("\n��������%d ...\n", (i+1));

	int c ;    //����IP��MAC�б��е����
	while(1){
		if(sentOnce){
			printf("�����Լ�����������,������IP��ַ:\n");
		}else{
			printf("���ڻ�ȡ��������MAC��ַ,���Ժ�....\n");
		}
		u_int ip1,ip2,ip3,ip4;
		
		bool legal = false;
		while(!legal){
			scanf_s("%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
			if(ip1<0||ip1>255||ip2<0||ip2>255||ip3<0||ip3>255||ip4<1||ip4>254){
				legal = false;
				printf("�Բ���,IP���벻�Ϸ�,����������:\n");
			}else{
				legal = true;
			}
		}
		printf("��������Ҫ���͵�����:\n");
		getchar();
		gets_s(TcpData);
		printf("Ҫ���͵�����:%s\n",TcpData);
		//�ṹ���ʼ��Ϊ0����
		memset(&ethernet, 0, sizeof(ethernet));
		printf("�������м�·�ɵ�MAC��ַ:\n");
		gets(route_mac);
		printf("·��MAC��ַΪ:%s\n",route_mac);
		//��ʼ�ָ�MAC��ַ
	    BYTE destmac[6];
		const char delim[]="-";
		char *next_toke = nullptr;
		char *strToke = nullptr,*str;
		strToke = strtok_s(route_mac,delim,&next_toke);
		destmac[0] = (int)strtol(strToke, &str, 16);
		strToke = strtok_s(nullptr,delim,&next_toke);
		destmac[1] = (int)strtol(strToke, &str, 16);
		strToke = strtok_s(nullptr,delim,&next_toke);
		destmac[2] = (int)strtol(strToke, &str, 16);
		strToke = strtok_s(nullptr,delim,&next_toke);
		destmac[3] = (int)strtol(strToke, &str, 16);
	    strToke = strtok_s(nullptr,delim,&next_toke);
		destmac[4] = (int)strtol(strToke, &str, 16);
		strToke = strtok_s(nullptr,delim,&next_toke);
		destmac[5] = (int)strtol(strToke, &str, 16);
		//��ֵĿ��MAC��ַ
		memcpy(ethernet.DestMAC, destmac, 6);
		BYTE hostmac[6];
		//ԴMAC��ַ
		hostmac[0] = local_mac[0];     //��ֵ����MAC��ַ
		hostmac[1] = local_mac[1];
		hostmac[2] = local_mac[2];
		hostmac[3] = local_mac[3];
		hostmac[4] = local_mac[4];
		hostmac[5] = local_mac[5];
		//��ֵԴMAC��ַ
		memcpy(ethernet.SourMAC, hostmac, 6);
		//�ϲ�Э������,0x0800����IPЭ��
		ethernet.EthType = htons(0x0800);
		//��ֵSendBuffer
		memcpy(&SendBuffer, &ethernet, sizeof(struct EthernetHeader));
		//��ֵIPͷ����Ϣ
		ip.Version_HLen = 0x45;
		ip.TOS = 0;
		ip.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
		ip.Ident = htons(1);
		ip.Flags_Offset = 0;
		ip.TTL = 128;
		ip.Protocol = 6;
		ip.Checksum = 0;
		//ԴIP��ַ
		 //ԴIP��ַ �ָ�ip_addr Ȼ������
		//delims�Ƿָ���
		const char delims[]=".";
		char ip_addr_temp[20];
		//����IP��ַ�ĸ�������ֱֹ���޸�IP
		strcpy_s(ip_addr_temp,ip_addr);
		char *next_token = nullptr;
		char *strToken = nullptr;
		//��ʼ�ָ�IP,��ֵ��Դ��ַ�ֶ���
		strToken = strtok_s(ip_addr_temp,delims,&next_token);
		ip.SourceAddr.byte1 = atoi(strToken);
		strToken = strtok_s(nullptr,delims,&next_token);
		ip.SourceAddr.byte2 =  atoi(strToken);
		strToken = strtok_s(nullptr,delims,&next_token);
		ip.SourceAddr.byte3 = atoi(strToken);
		strToken = strtok_s(nullptr,delims,&next_token);
		ip.SourceAddr.byte4 =  atoi(strToken);
		//Ŀ��IP��ַ
		ip.DestinationAddr.byte1 = ip1;
		ip.DestinationAddr.byte2 = ip2;
		ip.DestinationAddr.byte3 = ip3;
		ip.DestinationAddr.byte4 = ip4;
		//��ֵSendBuffer
		memcpy(&SendBuffer[sizeof(struct EthernetHeader)], &ip, 20);
		//��ֵTCPͷ������
		tcp.DstPort = htons(102);
		tcp.SrcPort = htons(1000);
		tcp.SequenceNum = htonl(11);
		tcp.Acknowledgment = 0;
		tcp.HdrLen = 0x50;
		tcp.Flags = 0x18;
		tcp.AdvertisedWindow = htons(512);
		tcp.UrgPtr = 0;
		tcp.Checksum = 0;
		//��ֵSendBuffer
		memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &tcp, 20);
		//��ֵα�ײ�
		ptcp.SourceAddr = ip.SourceAddr;
		ptcp.DestinationAddr = ip.DestinationAddr;
		ptcp.Zero = 0;
		ptcp.Protcol = 6;
		ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));
		//������ʱ�洢��������������У���
		char TempBuffer[65535];
		memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
		memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
		memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
		//����TCP��У���
		tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
		//���°�SendBuffer��ֵ����Ϊ��ʱУ����Ѿ��ı䣬��ֵ�µ�
		memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
		memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
		//��ʼ��TempBufferΪ0���У��洢����������IPУ���
		memset(TempBuffer, 0, sizeof(TempBuffer));
		memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
		//����IPУ���
		ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
		//���°�SendBuffer��ֵ��IPУ����Ѿ��ı�
		memcpy(SendBuffer + sizeof(struct EthernetHeader), &ip, sizeof(struct IpHeader));
		//�������еĳ���
		int size = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData);
		int result = pcap_sendpacket(adhandle, SendBuffer,size);
		if (result != 0)
		{
			printf("Send Error!\n");
		} 
		else
		{   
			sentOnce = 1;
			printf("���ͳɹ�!\n");
		}

	}
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
				printf("����IP��ַ:%s\n",ipstr);
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask) {
				char *netmaskstr;
				netmaskstr = iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
				printf("������������:%s\n",netmaskstr);
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
		printf("\nARP�����ͳɹ�\n");
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
	printf("����MAC��ַ:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
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
			printf("��ȡMAC��ַ���,��������Ҫ���ͶԷ���IP��ַ:\n");
			break;
		}
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
			if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)) {
				ArpPacket *recv = (ArpPacket *) pkt_data;
				if (*(unsigned short *) (pkt_data + 20) == htons(ARP_REPLY)) {
					printf("-----------------------------------------------------\n");
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
					printf(" ��Ŀ:%d\n",con);
					printf("\n");
				}
			}
		}
		Sleep(10);
	}
	return 0;
}
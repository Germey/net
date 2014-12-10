#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#pragma pack(1)  //按一个字节内存对齐
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255

char *iptos(u_long in);       //u_long即为 unsigned long
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);   
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *local_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
DWORD WINAPI RouteThread(LPVOID lpParameter);
//IP地址格式
struct IpAddress
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

//帧头部结构体，共14字节
struct EthernetHeader
{
    u_char DestMAC[6];    //目的MAC地址 6字节
    u_char SourMAC[6];   //源MAC地址 6字节
    u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//IP头部结构体，共20字节
struct IpHeader
{
    unsigned char Version_HLen;   //版本信息4位 ，头长度4位 1字节
    unsigned char TOS;                    //服务类型    1字节
    short Length;                              //数据包长度 2字节
    short Ident;                                 //数据包标识  2字节
    short Flags_Offset;                    //标志3位，片偏移13位  2字节
    unsigned char TTL;                   //存活时间  1字节
    unsigned char Protocol;          //协议类型  1字节
    short Checksum;                       //首部校验和 2字节
	IpAddress SourceAddr;       //源IP地址   4字节
	IpAddress DestinationAddr; //目的IP地址  4字节
};

//TCP头部结构体，共20字节
struct TcpHeader
{
    unsigned short SrcPort;                        //源端口号  2字节
    unsigned short DstPort;                        //目的端口号 2字节
    unsigned int SequenceNum;               //序号  4字节
    unsigned int Acknowledgment;         //确认号  4字节
    unsigned char HdrLen;                         //首部长度4位，保留位6位 共10位
    unsigned char Flags;                              //标志位6位
    unsigned short AdvertisedWindow;  //窗口大小16位 2字节
    unsigned short Checksum;                  //校验和16位   2字节
    unsigned short UrgPtr;						  //紧急指针16位   2字节
};

//TCP伪首部结构体 12字节
struct PsdTcpHeader
{
	IpAddress SourceAddr;                     //源IP地址  4字节
	IpAddress DestinationAddr;             //目的IP地址 4字节
    char Zero;                                                    //填充位  1字节
    char Protcol;                                               //协议号  1字节
    unsigned short TcpLen;                           //TCP包长度 2字节
};

//28字节ARP帧结构
struct Arpheader {
	unsigned short HardwareType; //硬件类型
	unsigned short ProtocolType; //协议类型
	unsigned char HardwareAddLen; //硬件地址长度
	unsigned char ProtocolAddLen; //协议地址长度
	unsigned short OperationField; //操作字段
	unsigned char SourceMacAdd[6]; //源mac地址
	unsigned long SourceIpAdd; //源ip地址
	unsigned char DestMacAdd[6]; //目的mac地址
	unsigned long DestIpAdd; //目的ip地址
};

//arp包结构
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
	pcap_if_t  * alldevs;       //所有网络适配器
};

struct ip_mac_list{
	IpAddress ip;
	unsigned char mac[6];
};
int con = 0;
bool flag;
bool sentOnce = false;            //定义是否已经至少发送过一次
HANDLE routethread;     //转发数据的线程
unsigned char *local_mac;          //本机MAC地址
struct sparam sp;
struct gparam gp;
struct rparam rp;
ip_mac_list  list[256];                       //存储IP和MAC地址的对应表
//获得校验和的方法
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

	struct EthernetHeader ethernet;    //以太网帧头
    struct IpHeader ip;                            //IP头
    struct TcpHeader tcp;                      //TCP头
    struct PsdTcpHeader ptcp;             //TCP伪首部
	char *ip_addr;                                    //IP地址
	char *ip_netmask;                             //子网掩码
	char *route_mac;                          //中间路由的MAC地址
	unsigned char SendBuffer[200];       //发送队列
	char TcpData[80];   //发送内容
	pcap_if_t  * alldevs;                //所有网络适配器
	pcap_if_t  *d,*d2;					//选中的网络适配器
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	pcap_t *adhandle,*adhandle2;           //捕捉实例,是pcap_open返回的对象,adhandle是用来发送数据，adhandle2是用来接收数据
	int i = 0;                            //适配器计数变量
	HANDLE sendthread;      //发送ARP包线程
	HANDLE recvthread;       //接受ARP包线程

	ip_addr = (char *) malloc(sizeof(char) * 16); //申请内存存放IP地址
	if (ip_addr == NULL)
	{
		printf("申请内存存放IP地址失败!\n");
		return -1;
	}
	ip_netmask = (char *) malloc(sizeof(char) * 16); //申请内存存放NETMASK地址
	if (ip_netmask == NULL)
	{
		printf("申请内存存放NETMASK地址失败!\n");
		return -1;
	}
	local_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //申请内存存放MAC地址
	if (local_mac == NULL)
	{
		printf("申请内存存放MAC地址失败!\n");
		return -1;
	}
	route_mac = (char *) malloc(sizeof(char) *17); //申请内存存放中间路由的MAC地址
	if (route_mac == NULL)
	{
		printf("申请内存存放中间路由MAC地址失败!\n");
		return -1;
	}
	//获取本地适配器列表
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//结果为-1代表出现获取适配器列表失败
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)代表正常退出,exit(other)为非正常退出,这个值会传给操作系统
		exit(1);
	}

	for(d = alldevs;d !=NULL;d = d->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d->name);
		if(d->description){
			//打印适配器的描述信息
			printf("description:%s\n",d->description);
		}else{
			//适配器不存在描述信息
			printf("description:%s","no description\n");
		}

		 pcap_addr_t *a;       //网络适配器的地址用来存储变量
		 for(a = d->addresses;a;a = a->next){
			 //sa_family代表了地址的类型,是IPV4地址类型还是IPV6地址类型
			 switch (a->addr->sa_family)
			 {
				 case AF_INET:  //代表IPV4类型地址
					 printf("Address Family Name:AF_INET\n");
					 if(a->addr){
						 //->的优先级等同于括号,高于强制类型转换,因为addr为sockaddr类型，对其进行操作须转换为sockaddr_in类型
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
				 case AF_INET6: //代表IPV6类型地址
					 printf("Address Family Name:AF_INET6\n");
					 printf("this is an IPV6 address\n");
					 break;
				 default:
					 break;
			 }
		 }
	}
	//i为0代表上述循环未进入,即没有找到适配器,可能的原因为Winpcap没有安装导致未扫描到
	if(i == 0){
		printf("interface not found,please check winpcap installation");
	}

	int num;
	printf("请输入你要转发数据的网卡代号:");

	scanf_s("%d",&num);

	//跳转到选中的适配器
	for(d=alldevs, i=0; i< num-1 ; d=d->next, i++);

	//运行到此处说明用户的输入是合法的，找到发送数据网卡
	if((adhandle = pcap_open(d->name,		//设备名称
													65535,       //存放数据包的内容长度
													PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式
													1000,           //超时时间
													NULL,          //远程验证
													errbuf         //错误缓冲
													)) == NULL){
    //打开适配器失败,打印错误并释放适配器列表
	fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    // 释放设备列表 
    pcap_freealldevs(alldevs);
    return -1;
	}

	int num2;
	printf("请输入你要接收数据的网卡代号:");

	scanf_s("%d",&num2);
	//用户输入的数字超出合理范围


	//跳转到选中的适配器
	for(d2=alldevs, i=0; i< num2-1 ; d2=d2->next, i++);

	//运行到此处说明用户的输入是合法的
	if((adhandle2 = pcap_open(d2->name,		//设备名称
													65535,       //存放数据包的内容长度
													PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式
													1000,           //超时时间
													NULL,          //远程验证
													errbuf         //错误缓冲
													)) == NULL){
    //打开适配器失败,打印错误并释放适配器列表
	fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d2->name);
    // 释放设备列表 
    pcap_freealldevs(alldevs);
    return -1;
	}


	//运行到此处说明可以打开该设备，并且adhandle已经得到有效赋值。
	//传入选中的适配器,用来存储ip和掩码的变量
	ifget(d, ip_addr, ip_netmask); //获取所选网卡的基本信息--掩码--IP地址
	GetSelfMac(adhandle, ip_addr, local_mac); //输入网卡设备句柄网卡设备ip地址获取该设备的MAC地址
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
	//释放网络适配器列表
	pcap_freealldevs(alldevs);

	system("pause");
	return 0;

}

/* 将数字类型的IP地址转换成字符串类型的 */
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

/* 获取可用信息*/
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask) {
	pcap_addr_t *a;
	//遍历所有的地址,a代表一个pcap_addr
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family) {
		case AF_INET:  //sa_family ：是2字节的地址家族，一般都是“AF_xxx”的形式。通常用的都是AF_INET。代表IPV4
			if (a->addr) {
				char *ipstr;
				//将地址转化为字符串
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

/* 获取自己主机的MAC地址 */
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *local_mac) {
	unsigned char sendbuf[42]; //arp包结构大小
	int i = -1;
	int res;
	EthernetHeader eh; //以太网帧头
	Arpheader ah;  //ARP帧头
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	//将已开辟内存空间 eh.dest_mac_add 的首 6个字节的值设为值 0xff。
	memset(eh.DestMAC, 0xff, 6); //目的地址为全为广播地址
	memset(eh.SourMAC, 0x0f, 6);
	memset(ah.DestMacAdd, 0x0f, 6);
	memset(ah.SourceMacAdd, 0x00, 6);
	//htons将一个无符号短整型的主机数值转换为网络字节顺序
	eh.EthType = htons(ETH_ARP);
	ah.HardwareType= htons(ARP_HARDWARE);
	ah.ProtocolType = htons(ETH_IP);
	ah.HardwareAddLen = 6;
	ah.ProtocolAddLen = 4;
	ah.SourceIpAdd = inet_addr("100.100.100.100"); //随便设的请求方ip
	ah.OperationField = htons(ARP_REQUEST);
	ah.DestIpAdd = inet_addr(ip_addr);
	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nARP请求发送成功,即将获取到自身MAC地址\n");
	} else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;
	}
	//从interface或离线记录文件获取一个报文
	//pcap_next_ex(pcap_t* p,struct pcap_pkthdr** pkt_header,const u_char** pkt_data)
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)
				&& *(unsigned short*) (pkt_data + 20) == htons(ARP_REPLY)
				&& *(unsigned long*) (pkt_data + 38)
						== inet_addr("100.100.100.100")) {
			for (i = 0; i < 6; i++) {
				local_mac[i] = *(unsigned char *) (pkt_data + 22 + i);
			}
			printf("获取自己主机的MAC地址成功!\n");
			break;
		}
	}
	if (i == 6) {
		return 1;
	} else {
		return 0;
	}
}
/* 向局域网内所有可能的IP地址发送ARP请求包线程 */
DWORD WINAPI SendArpPacket(LPVOID lpParameter) //(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
	sparam *spara = (sparam *) lpParameter;
	pcap_t *adhandle = spara->adhandle;
	char *ip = spara->ip;
	unsigned char *mac = spara->mac;
	char *netmask = spara->netmask;
	printf("local_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	printf("自身的IP地址为:%s\n", ip);
	printf("地址掩码NETMASK为:%s\n", netmask);
	printf("\n");
	unsigned char sendbuf[42]; //arp包结构大小
	EthernetHeader eh;
	Arpheader ah;
	memset(eh.DestMAC, 0xff, 6);       //目的地址为全为广播地址
	memcpy(eh.SourMAC, mac, 6);
	memcpy(ah.SourceMacAdd, mac, 6);
	memset(ah.DestMacAdd, 0x00, 6);
	eh.EthType = htons(ETH_ARP);
	ah.HardwareType = htons(ARP_HARDWARE);
	ah.ProtocolType = htons(ETH_IP);
	ah.HardwareAddLen = 6;
	ah.ProtocolAddLen = 4;
	ah.SourceIpAdd = inet_addr(ip); //请求方的IP地址为自身的IP地址
	ah.OperationField = htons(ARP_REQUEST);
	//向局域网内广播发送arp包
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
/* 分析截留的数据包获取活动的主机IP地址 */
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
			printf("获取MAC地址完毕\n");
			routethread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) RouteThread, &rp,
			0, NULL);
			break;
		}
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
			if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)) {
				ArpPacket *recv = (ArpPacket *) pkt_data;
				if (*(unsigned short *) (pkt_data + 20) == htons(ARP_REPLY)) {
					printf("-------------------------------------------\n");
					printf("IP地址:%d.%d.%d.%d   MAC地址:",
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
					printf("  个数:%d\n",con);
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
	struct pcap_pkthdr *header;    //接收到的数据包的头部
    const u_char *pkt_data;			  //接收到的数据包的内容
	EthernetHeader *ethernet;    //以太网帧头
    IpHeader *ip;                            //IP头
    TcpHeader *tcp;               
	unsigned char *sou_mac;      //源MAC
	unsigned char *des_mac;      //目的MAC
	u_int ip_len;  
	pcap_if_t *alldevs;
	pcap_t *adhandle,*adhandle2;
	alldevs = rpara->alldevs;
	adhandle = rpara->adhandle_send;
	adhandle2 = rpara->adhandle_rec;
	unsigned char SendBuffer[2000];       //发送队列
	char * data;
	//打印输出,正在监听中
	struct EthernetHeader send_ethernet;    //以太网帧头
	struct IpHeader send_ip;                            //IP头
    struct TcpHeader send_tcp;                      //TCP头
	struct PsdTcpHeader send_ptcp;                //伪首部
	//为源MAC地址开辟地址空间
	sou_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //申请内存存放MAC地址
	if (sou_mac == NULL)
	{
		printf("申请存放源MAC地址失败!\n");
		return -1;
	}
	//为目的IP开辟地址空间
	des_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //申请内存存放MAC地址
	if (des_mac == NULL)
	{
		printf("申请存放目的MAC地址失败!\n");
		return -1;
	}

        netmask=0xffffff;

	if(pcap_compile(adhandle2,	//适配器处理对象
										&fcode,
										packet_filter,   //过滤ip和UDP
										1,                       //优化标志
										netmask           //子网掩码
										)<0)
	{
		//过滤出现问题
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
	}

	//设置过滤器
    if (pcap_setfilter(adhandle2, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        //释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

	//利用pcap_next_ex来接受数据包
	while((res = pcap_next_ex(adhandle2,&header,&pkt_data))>=0)
	{
		if(res ==0){
			//返回值为0代表接受数据包超时，重新循环继续接收
			continue;
		}else{
			printf("收到了新数据!!!\n");
			printf("-----------------------------------------------------------\n");
			//运行到此处代表接受到正常从数据包
			ethernet =  (EthernetHeader *)(pkt_data);
			for(int i=0;i<6;i++){
				sou_mac[i] = ethernet->SourMAC[i];
			}
			for(int i=0;i<6;i++){
				des_mac[i] = ethernet->DestMAC[i];
			}
			// 获得IP数据包头部的位置
			ip = (IpHeader *) (pkt_data +14);    //14为以太网帧头部长度
			//获得TCP头部的位置
			ip_len = (ip->Version_HLen & 0xf) *4;
			tcp = (TcpHeader *)((u_char *)ip+ip_len);
			data = (char *)((u_char *)tcp+20);
			printf("内容:%s\n",data);
			printf("源IP: %d.%d.%d.%d -> 目的IP: %d.%d.%d.%d\n",
					ip->SourceAddr.byte1,
					ip->SourceAddr.byte2,
					ip->SourceAddr.byte3,
					ip->SourceAddr.byte4,
				    ip->DestinationAddr.byte1,
				    ip->DestinationAddr.byte2,
				    ip->DestinationAddr.byte3,
				    ip->DestinationAddr.byte4);
			 printf("源MAC地址:%02x-%02x-%02x-%02x-%02x-%02x\n", sou_mac[0], sou_mac[1], sou_mac[2],
			    sou_mac[3], sou_mac[4], sou_mac[5]);
			printf("目的MAC地址:%02x-%02x-%02x-%02x-%02x-%02x\n", des_mac[0], des_mac[1], des_mac[2],
			    des_mac[3], des_mac[4], des_mac[5]);
		}
		//以下开始构建帧发送
		//首先判断data最大值小于1500
		if(strlen(data)<1500){
			//目的MAC
			BYTE send_destmac[6];
			bool findMac = false;
			for(int c = 0;c<con;c++){
				if(ip->DestinationAddr.byte1 ==  list[c].ip.byte1&&
					ip->DestinationAddr.byte2 == list[c].ip.byte2&&
					ip->DestinationAddr.byte3 == list[c].ip.byte3&&
					ip->DestinationAddr.byte4 == list[c].ip.byte4)
				{
					printf("在局域网内找到了它的MAC!\n");
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
			printf("新构建的帧:\n");
			printf("目的MAC :%02x-%02x-%02x-%02x-%02x-%02x\n",
				send_destmac[0],send_destmac[1],send_destmac[2],
				send_destmac[3],send_destmac[4],send_destmac[5]
				);
			memcpy(send_ethernet.DestMAC, send_destmac, 6);
			//源MAC地址
			BYTE send_hostmac[6];
			//源MAC地址
			send_hostmac[0] = local_mac[0];     //赋值本地MAC地址
			send_hostmac[1] = local_mac[1];
			send_hostmac[2] = local_mac[2];
			send_hostmac[3] = local_mac[3];
			send_hostmac[4] = local_mac[4];
			send_hostmac[5] = local_mac[5];
			printf("源MAC :%02x-%02x-%02x-%02x-%02x-%02x\n",
				send_hostmac[0],send_hostmac[1],send_hostmac[2],
				send_hostmac[3],send_hostmac[4],send_hostmac[5]
				);
			printf("源IP: %d.%d.%d.%d -> 目的IP: %d.%d.%d.%d\n",
					ip->SourceAddr.byte1,
					ip->SourceAddr.byte2,
					ip->SourceAddr.byte3,
					ip->SourceAddr.byte4,
				    ip->DestinationAddr.byte1,
				    ip->DestinationAddr.byte2,
				    ip->DestinationAddr.byte3,
				    ip->DestinationAddr.byte4);
			//赋值源MAC地址
			memcpy(send_ethernet.SourMAC, send_hostmac, 6);
			send_ethernet.EthType = htons(0x0800);
			//赋值SendBuffer
			memcpy(&SendBuffer, &send_ethernet, sizeof(struct EthernetHeader));
			//赋值IP头部信息
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
			//赋值TCP头部内容
			send_tcp.DstPort = htons(102);
			send_tcp.SrcPort = htons(1000);
			send_tcp.SequenceNum = htonl(11);
			send_tcp.Acknowledgment = 0;
			send_tcp.HdrLen = 0x50;
			send_tcp.Flags = 0x18;
			send_tcp.AdvertisedWindow = htons(512);
			send_tcp.UrgPtr = 0;
			send_tcp.Checksum = 0;
			//赋值SendBuffer
			memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &send_tcp, 20);
			//赋值伪首部
			send_ptcp.SourceAddr = send_ip.SourceAddr;
			send_ptcp.DestinationAddr = send_ip.DestinationAddr;
			send_ptcp.Zero = 0;
			send_ptcp.Protcol = 6;
			send_ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(data));
			//声明临时存储变量，用来计算校验和
			char TempBuffer[65535];
			memcpy(TempBuffer, &send_ptcp, sizeof(struct PsdTcpHeader));
			memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &send_tcp, sizeof(struct TcpHeader));
			memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), data, strlen(data));
			//计算TCP的校验和
			send_tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(data));
			//重新把SendBuffer赋值，因为此时校验和已经改变，赋值新的
			memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &send_tcp, sizeof(struct TcpHeader));
			memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), data, strlen(data));
			//初始化TempBuffer为0序列，存储变量来计算IP校验和
			memset(TempBuffer, 0, sizeof(TempBuffer));
			memcpy(TempBuffer, &send_ip, sizeof(struct IpHeader));
			//计算IP校验和
			send_ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
			//重新把SendBuffer赋值，IP校验和已经改变
			memcpy(SendBuffer + sizeof(struct EthernetHeader), &send_ip, sizeof(struct IpHeader));
			//发送序列的长度
			int size = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(data);
			int result = pcap_sendpacket(adhandle, SendBuffer,size);   //用adhandle发送
			if (result != 0)
			{
				printf("Send Error!\n");
			} 
			else
			{   
				printf("发送成功!\n");
			}
		}

	}//while

}
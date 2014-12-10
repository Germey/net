#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>


char *iptos(u_long in);       //u_long即为 unsigned long
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//struct tm *ltime;					//和时间处理有关的变量

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
    unsigned char TTL;                    //存活时间  1字节
    unsigned char Protocol;           //协议类型  1字节
    short Checksum;                        //首部校验和 2字节
    IpAddress SourceAddr;           //源IP地址   4字节
    IpAddress DestinationAddr;   //目的IP地址  4字节
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
    unsigned long SourceAddr;                     //源IP地址  4字节
    unsigned long DestinationAddr;             //目的IP地址 4字节
    char Zero;                                                    //填充位  1字节
    char Protcol;                                               //协议号  1字节
    unsigned short TcpLen;                           //TCP包长度 2字节
};


int main(){

	EthernetHeader *ethernet;    //以太网帧头
    IpHeader *ip;                            //IP头
    TcpHeader *tcp;                      //TCP头
    PsdTcpHeader *ptcp;             //TCP伪首部
	unsigned char *sou_mac;      //源MAC
	unsigned char *des_mac;      //目的MAC
	pcap_if_t  * alldevs;       //所有网络适配器
	pcap_if_t  *d;					//选中的网络适配器
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	char source[PCAP_ERRBUF_SIZE];
	pcap_t *adhandle;           //捕捉实例,是pcap_open返回的对象
	int i = 0;                            //适配器计数变量
	struct pcap_pkthdr *header;    //接收到的数据包的头部
    const u_char *pkt_data;			  //接收到的数据包的内容
	int res;                                    //表示是否接收到了数据包
	u_int netmask;                       //过滤时用的子网掩码
	char packet_filter[] = "tcp";        //过滤字符
	struct bpf_program fcode;                     //pcap_compile所调用的结构体

	u_int ip_len;                                       //ip地址有效长度
	u_short sport,dport;                        //主机字节序列
	u_char packet[100];                       //发送数据包目的地址
	pcap_dumper_t *dumpfile;         //堆文件

	//time_t local_tv_sec;				//和时间处理有关的变量
    //char timestr[16];					//和时间处理有关的变量
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
	//获取本地适配器列表
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//结果为-1代表出现获取适配器列表失败
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)代表正常退出,exit(other)为非正常退出,这个值会传给操作系统
		exit(1);
	}
	//打印设备列表信息
	for(d = alldevs;d !=NULL;d = d->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d->name);
		if(d->description){
			//打印适配器的描述信息
			printf("description:%s\n",d->description);
		}else{
			//适配器不存在描述信息
			printf("description:%s","no description\n");
		}
		//打印本地环回地址
		printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
		
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
	printf("请输入要打开的网卡代号(1-%d):",i);
	//让用户选择选择哪个适配器进行抓包
	scanf_s("%d",&num);
	printf("\n");

	//用户输入的数字超出合理范围
	if(num<1||num>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//跳转到选中的适配器
	for(d=alldevs, i=0; i< num-1 ; d=d->next, i++);

	//运行到此处说明用户的输入是合法的
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
	

	//打印输出,正在监听中
	printf("\n监听 %s...\n", d->description);

	//所在网络是以太网,此处只取这种情况
	if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        //释放列表
        pcap_freealldevs(alldevs);
        return -1;
    }

	//先获得地址的子网掩码
	if(d->addresses != NULL)
        //获得接口第一个地址的掩码 
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        // 如果接口没有地址，那么我们假设一个C类的掩码
        netmask=0xffffff;

	//pcap_compile()的原理是将高层的布尔过滤表
	//达式编译成能够被过滤引擎所解释的低层的字节码
	if(pcap_compile(adhandle,	//适配器处理对象
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
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        //释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

	//设置要接收的目的IP地址,填写0.0.0.0表示全部接收
	printf("请输入要接收的IP地址,输入0.0.0.0代表全部接收,请输入\n");
	bool receiveAll = false;
	u_int ip1,ip2,ip3,ip4;
	bool legal = false;
	while(!legal){
		scanf_s("%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
		if(ip1==0&&ip2==0&&ip3==0&&ip4==0){
			receiveAll = true;
			legal = true;
			break;
		}
		if(ip1<0||ip1>255||ip2<0||ip2>255||ip3<0||ip3>255||ip4<1||ip4>254){
			legal = false;
			printf("对不起,IP输入不合法,请重新输入:\n");
		}else{
			legal = true;
		}
	}

	//利用pcap_next_ex来接受数据包
	while((res = pcap_next_ex(adhandle,&header,&pkt_data))>=0)
	{
		if(res ==0){
			//返回值为0代表接受数据包超时，重新循环继续接收
			continue;
		}else{
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
			char * data;
			 data = (char *)((u_char *)tcp+20);
			 //将网络字节序列转换成主机字节序列
			sport = ntohs( tcp->SrcPort );
			dport = ntohs( tcp->DstPort );
			if(receiveAll||(ip->SourceAddr.byte1==ip1&&
					ip->SourceAddr.byte2==ip2&&
					ip->SourceAddr.byte3==ip3&&
					ip->SourceAddr.byte4==ip4)){
					printf("源IP %d.%d.%d.%d.%d ->目的IP %d.%d.%d.%d.%d\n",
					ip->SourceAddr.byte1,
					ip->SourceAddr.byte2,
					ip->SourceAddr.byte3,
					ip->SourceAddr.byte4,
				    sport,
				    ip->DestinationAddr.byte1,
				    ip->DestinationAddr.byte2,
				    ip->DestinationAddr.byte3,
				    ip->DestinationAddr.byte4,
				    dport);
			    printf("源MAC地址:%02x-%02x-%02x-%02x-%02x-%02x\n", sou_mac[0], sou_mac[1], sou_mac[2],
			    sou_mac[3], sou_mac[4], sou_mac[5]);
				printf("目标MAC地址:%02x-%02x-%02x-%02x-%02x-%02x\n", des_mac[0], des_mac[1], des_mac[2],
			    des_mac[3], des_mac[4], des_mac[5]);
				printf("%s\n",data);
				printf("-----------------------------------------------------\n");
			}
		}

	}

	
	//释放网络适配器列表
	pcap_freealldevs(alldevs);

	/**
	int pcap_loop  ( pcap_t *  p,  
								  int  cnt,  
								  pcap_handler  callback,  
								  u_char *  user   
								 );
     typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
                 const u_char *);
	*/
	//开始捕获信息,当捕获到数据包时,会自动调用这个函数
	//pcap_loop(adhandle,0,packet_handler,NULL);

	int inum;
	scanf_s("%d", &inum);

	return 0;

}

/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
/**
pcap_loop()函数是基于回调的原理来进行数据捕获的，如技术文档所说，这是一种精妙的方法，并且在某些场合下，
它是一种很好的选择。但是在处理回调有时候会并不实用，它会增加程序的复杂度，特别是在多线程的C++程序中
*/
/*
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime = NULL;
    char timestr[16];
    time_t local_tv_sec;

    // 将时间戳转换成可识别的格式
    local_tv_sec = header->ts.tv_sec;
    localtime_s(ltime,&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);

}
*/
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

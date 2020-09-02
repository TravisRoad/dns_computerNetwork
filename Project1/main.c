#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <time.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 53
#define BUFFER_SIZE 1024

const char* SERVER_IP = "10.3.9.4";//默认名字服务器ip
const char* LOCAL_FILE = "dnsrelay.txt";//默认配置文件名

/*Dns结构的三个部分：head、问题、资源记录*/
typedef struct DNSHEADER {
	unsigned short ID;
	unsigned short Flag;
	unsigned short Qdcount;
	unsigned short Ancount;
	unsigned short Nscount;
	unsigned short Arcount;
}DNSHEADER;			//dns头

typedef struct DNSQUESTION {
	unsigned short Qtype;
	unsigned short Qclass;
}DNSQUESTION;		//dns问题

typedef struct DNSRESOURCE {
	unsigned short Type;
	unsigned short Class;
	unsigned int TTL;
	unsigned short Length;
}DNSRESOURCE;		//dns资源记录（答案）


//链表结构，用来保存本地ip-addr映射关系
typedef struct Node {
	char domainName[100];
	char ip[20];
	struct Node* next;
}Node;

Node* head = NULL;

/*
* 链表插入函数， 需要事先声明一个头节点指针
*/
void insert(char* domain, char* ip) {
	Node* current;
	if (head == NULL) current = head = (Node*)malloc(sizeof(Node));
	else {
		Node* tmp = head;
		while (tmp->next != NULL)
			tmp = tmp->next;
		current = tmp->next = (Node*)malloc(sizeof(Node));
	}
	strcpy(current->domainName, domain);
	strcpy(current->ip, ip);
	current->next = NULL;
}

/*
* 从LRU缓存池中查询,存在则返回1，否则0
* dn为域名字符串,ip为要放入ip地址的空间
*/
int findDomainLRU(char* dn, char* ip) {
	return 0;
}

///*
//* 构造响应报文
//* 响应报文存放在buf里面
//* ip是取得的ip，level为调试等级
//*/
//void Respond(char* buf, char* ip, int level) {
//
//}

/*
* 构造响应报文，在主机中查询到时使用，主要是通过更改查询报文实现的
* buf为询问报文，ip为查询到的IP地址，level为调试等级，只有调试等级为2时，会输出不安全信息
*/
void Respond(char* buf, char* ip, int level) {
	DNSHEADER* header = (DNSHEADER*)buf;
	DNSRESOURCE* resouce;

	/*IP为0.0.0.0响应报文flag中的RCODE为0x3，表示域名不存在*/
	if (ip[0] == (char)0 && ip[1] == (char)0 && ip[2] == (char)0 && ip[3] == (char)0) {
		/*调试等级为2时才会输出*/
		if (level == 2)
			printf("IPaddr is 0.0.0.0, the domainname is unsafe.\n");
		header->Flag = htons(0x8183);
	}
	/*正常情况的响应报文flag为0x8180*/
	else {
		header->Flag = htons(0x8180);
	}
	/*回答数为1*/
	header->Ancount = htons(1);

	char* dn = buf + 12;							//指向报文中的question头
	char* name = dn + strlen(dn) + 1 + 4;			//指向报文中的answer头
	unsigned short* nameTemp = (unsigned short*)name;
	*nameTemp = htons(0xC00C);						//将answer的前两个字节写成0xC0
	/*对answer部分进行填写*/
	resouce = (DNSRESOURCE*)(name + 2);
	resouce->Type = htons(1);
	resouce->Class = htons(1);
	resouce->TTL = htons(0x0FFF);
	resouce->Length = htons(4);
	/*填入IP答案*/
	char* data = (char*)resouce + 10;
	*data = *ip;
	*(data + 1) = *(ip + 1);
	*(data + 2) = *(ip + 2);
	*(data + 3) = *(ip + 3);
}

/*
* 将ip-addr读入内存
*/
void openFile(char* filename, int level) {
	FILE* fptr = fopen(filename, "r");
	if (fptr == NULL) {
		printf("file error");
		exit(1);
	}
	char dn[100], ip[20];
	while (!feof(fptr)) {
		fscanf(fptr, "%s %s", ip, dn);
		insert(dn, ip);
	}
	printf("文件已读入\n");
}

/*
* 域名是否存在,存在则返回1，否则返回0
*/
int findDomain(char* dn, char* ip) {
	Node* tmp = head;
	char* ipPtr = NULL;
	while (tmp->next != NULL) {
		if (strcmp(dn, tmp->domainName) == 0) {
			ipPtr = tmp->ip;
			break;
		}
		tmp = tmp->next;
	}
	if (ipPtr == NULL) return 0;
	else {
		int sum = 0;//暂时存储
		while (*ipPtr != 0) {
			if (*ipPtr != '.') {
				sum = sum * 10 + *ipPtr - '0';
			}
			else {
				*ip = sum;
				ip++;//指针下移
				sum = 0;//清空
			}
			ipPtr++;
		}
		return 1;
	}
}

/*将报文中的域名转化为可读的域名*/
void ToDomainName(char* buf) {
	char* p = buf;
	while (*p != 0) {
		if (*p < 48) *p = '.';//转为'.'
		else if (*p <= 'Z' && *p >= 'A') *p += 32;//转小写
		p++;
	}
}

void dns_init() {

}

void dns_debug_0() {
	char buf[BUFFER_SIZE];//用来保存包的信息

	/*准备UDP通信*/
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("error\n");
		exit(1);
	}
	/*创建与客户端沟通的套接字*/
	SOCKET socketClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socketClient == SOCKET_ERROR) {
		printf("Creat client Socket Error\n");
		exit(1);
	}
	/*主机，作为服务器，绑定IP和端口*/
	SOCKADDR_IN server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	/*客户端，不需要设置信息*/
	SOCKADDR_IN client;

	/*绑定*/
	int x = bind(socketClient, (struct sockaddr*)&server, sizeof(server));
	if (x != 0) {
		printf("bind error\n");
		exit(1);
	}

	/*创建了与dns服务器沟通的套接字*/
	SOCKET DnsFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (DnsFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}

	/*设置接收非阻塞，防止包丢失后在循环中卡住*/
	int timeout = 2000;
	setsockopt(DnsFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));

	/*dns服务器，绑定IP和端口*/
	SOCKADDR_IN Dns;
	Dns.sin_family = AF_INET;
	Dns.sin_port = htons(PORT);
	Dns.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);

	char* temp = (char*)malloc(BUFFER_SIZE);	//存放域名
	char* ip = (char*)malloc(4);				//IP的区域
	int len = sizeof(client);
	while (1) {
		memset(buf, 0, BUFFER_SIZE);//用0填充buf

		/*从客户端接收信息，接收失败则进行下一步循环*/
		x = recvfrom(socketClient, buf, BUFFER_SIZE, 0, (struct sockaddr*)&client, &len);
		if (x < 0) {
			continue;
		}
		/*将域名赋值到temp数组中*/
		strcpy(temp, buf + sizeof(DNSHEADER) + 1);
		ToDomainName(temp);//预处理

		int isFind = 0;
		/*从LRU缓存池中查询*/
		isFind = findDomainLRU(temp, ip);

		/*查询到结果则构造响应报文*/
		if (isFind == 1) {
			Respond(buf, ip, 0);
		}
		/*未查询到，需要先访问本地链表，再访问上层的dns服务器进行查询*/
		else {//if(isFind == 1)
			/*LRU没有，则从链表中查询*/
			isFind = findDomain(temp, ip);
			/*查询到结果则构造响应报文*/
			if (isFind == 1) {
				Respond(buf, ip, 0);
			}
			else {
				//FIFO未完成

				/*将查询包原封不动的发送给dns服务器*/
				sendto(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&Dns, sizeof(Dns));

				unsigned short id = *(unsigned short*)buf;//最前面的字节
				unsigned short idtemp;
				int i = sizeof(Dns);
				unsigned int j;
				/*只在响应包与查询包的id相同时才停止接收，
				*由于接收的方式采用了非阻塞，当超过设置的超时时间时，会自动返回一个没有答案的响应包
				*如果dns服务器之前发送的响应包到达比较晚，那么就会与现在所询问的不符合，就会产生所答非所问的情况，所以需要进行一次筛选
				*/
				do
				{
					j = recvfrom(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&Dns, &i);
					idtemp = *(unsigned short*)buf;
				} while (idtemp != id);
			}
		}
		/*将响应包原封不动的转发给客户端，发送失败则不断重发至发送成功*/
		int tmp = 0;
		do
		{
			tmp = sendto(socketClient, buf, sizeof(buf), 0, (struct sockaddr*)&client, sizeof(client));
		} while (tmp < 0);
	}
}
/*调试信息接级别1*/
void dns_debug_1() {

}
/*调试信息接级别2*/
void dns_debug_2() {

}
int main(int argc, char** argv)
{
	printf("\nDNSRELAY, Version 0.1 Build:%s\n", __DATE__);
	printf("Usage: dnsrelay [-d|-dd] [<dns-server>] [<db-file>]\n\n");
	// init(argc,argv);
	if (argc == 1) {
		printf("调试信息接级别0 无调试信息输出\n");
		printf("指定名字服务器为 %s:53\n", SERVER_IP);
		printf("使用默认配置文件 %s\n", LOCAL_FILE);
		openFile((char*)LOCAL_FILE, 0);
		dns_debug_0();
	}
	else if (argc == 4 && strcmp(argv[1], "-d") == 0) {
		printf("调试信息接级别1 简单调试信息输出\n");
		printf("指定名字服务器为 %s:53\n", argv[2]);
		printf("使用指定配置文件 %s\n", argv[3]);
		openFile(argv[3], 1);
		//dns_debug_1(argv[2], argv[3]);
	}
	else if (argc == 3 && strcmp(argv[1], "-dd") == 0) {
		printf("调试信息接级别2 复杂调试信息输出\n");
		printf("指定名字服务器为 %s:53\n", argv[2]);
		printf("使用默认配置文件 %s\n", LOCAL_FILE);
		openFile((char*)LOCAL_FILE, 2);
		//dns_debug_2(argv[2]);
	}
	else {
		printf("参数输入有误，请重新输入\n");
	}
	//printf("%d\n", domainIsExist("h0"));
	printf("hello\n");
	return 0;
}
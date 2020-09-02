#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <time.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 53
#define BUFFER_SIZE 1024

const char* SERVER_IP = "10.3.9.4";//Ĭ�����ַ�����ip
const char* LOCAL_FILE = "dnsrelay.txt";//Ĭ�������ļ���

/*Dns�ṹ���������֣�head�����⡢��Դ��¼*/
typedef struct DNSHEADER {
	unsigned short ID;
	unsigned short Flag;
	unsigned short Qdcount;
	unsigned short Ancount;
	unsigned short Nscount;
	unsigned short Arcount;
}DNSHEADER;			//dnsͷ

typedef struct DNSQUESTION {
	unsigned short Qtype;
	unsigned short Qclass;
}DNSQUESTION;		//dns����

typedef struct DNSRESOURCE {
	unsigned short Type;
	unsigned short Class;
	unsigned int TTL;
	unsigned short Length;
}DNSRESOURCE;		//dns��Դ��¼���𰸣�


//����ṹ���������汾��ip-addrӳ���ϵ
typedef struct Node {
	char domainName[100];
	char ip[20];
	struct Node* next;
}Node;

Node* head = NULL;

/*
* ������뺯���� ��Ҫ��������һ��ͷ�ڵ�ָ��
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
* ��LRU������в�ѯ,�����򷵻�1������0
* dnΪ�����ַ���,ipΪҪ����ip��ַ�Ŀռ�
*/
int findDomainLRU(char* dn, char* ip) {
	return 0;
}

///*
//* ������Ӧ����
//* ��Ӧ���Ĵ����buf����
//* ip��ȡ�õ�ip��levelΪ���Եȼ�
//*/
//void Respond(char* buf, char* ip, int level) {
//
//}

/*
* ������Ӧ���ģ��������в�ѯ��ʱʹ�ã���Ҫ��ͨ�����Ĳ�ѯ����ʵ�ֵ�
* bufΪѯ�ʱ��ģ�ipΪ��ѯ����IP��ַ��levelΪ���Եȼ���ֻ�е��Եȼ�Ϊ2ʱ�����������ȫ��Ϣ
*/
void Respond(char* buf, char* ip, int level) {
	DNSHEADER* header = (DNSHEADER*)buf;
	DNSRESOURCE* resouce;

	/*IPΪ0.0.0.0��Ӧ����flag�е�RCODEΪ0x3����ʾ����������*/
	if (ip[0] == (char)0 && ip[1] == (char)0 && ip[2] == (char)0 && ip[3] == (char)0) {
		/*���Եȼ�Ϊ2ʱ�Ż����*/
		if (level == 2)
			printf("IPaddr is 0.0.0.0, the domainname is unsafe.\n");
		header->Flag = htons(0x8183);
	}
	/*�����������Ӧ����flagΪ0x8180*/
	else {
		header->Flag = htons(0x8180);
	}
	/*�ش���Ϊ1*/
	header->Ancount = htons(1);

	char* dn = buf + 12;							//ָ�����е�questionͷ
	char* name = dn + strlen(dn) + 1 + 4;			//ָ�����е�answerͷ
	unsigned short* nameTemp = (unsigned short*)name;
	*nameTemp = htons(0xC00C);						//��answer��ǰ�����ֽ�д��0xC0
	/*��answer���ֽ�����д*/
	resouce = (DNSRESOURCE*)(name + 2);
	resouce->Type = htons(1);
	resouce->Class = htons(1);
	resouce->TTL = htons(0x0FFF);
	resouce->Length = htons(4);
	/*����IP��*/
	char* data = (char*)resouce + 10;
	*data = *ip;
	*(data + 1) = *(ip + 1);
	*(data + 2) = *(ip + 2);
	*(data + 3) = *(ip + 3);
}

/*
* ��ip-addr�����ڴ�
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
	printf("�ļ��Ѷ���\n");
}

/*
* �����Ƿ����,�����򷵻�1�����򷵻�0
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
		int sum = 0;//��ʱ�洢
		while (*ipPtr != 0) {
			if (*ipPtr != '.') {
				sum = sum * 10 + *ipPtr - '0';
			}
			else {
				*ip = sum;
				ip++;//ָ������
				sum = 0;//���
			}
			ipPtr++;
		}
		return 1;
	}
}

/*�������е�����ת��Ϊ�ɶ�������*/
void ToDomainName(char* buf) {
	char* p = buf;
	while (*p != 0) {
		if (*p < 48) *p = '.';//תΪ'.'
		else if (*p <= 'Z' && *p >= 'A') *p += 32;//תСд
		p++;
	}
}

void dns_init() {

}

void dns_debug_0() {
	char buf[BUFFER_SIZE];//�������������Ϣ

	/*׼��UDPͨ��*/
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("error\n");
		exit(1);
	}
	/*������ͻ��˹�ͨ���׽���*/
	SOCKET socketClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socketClient == SOCKET_ERROR) {
		printf("Creat client Socket Error\n");
		exit(1);
	}
	/*��������Ϊ����������IP�Ͷ˿�*/
	SOCKADDR_IN server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	/*�ͻ��ˣ�����Ҫ������Ϣ*/
	SOCKADDR_IN client;

	/*��*/
	int x = bind(socketClient, (struct sockaddr*)&server, sizeof(server));
	if (x != 0) {
		printf("bind error\n");
		exit(1);
	}

	/*��������dns��������ͨ���׽���*/
	SOCKET DnsFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (DnsFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}

	/*���ý��շ���������ֹ����ʧ����ѭ���п�ס*/
	int timeout = 2000;
	setsockopt(DnsFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));

	/*dns����������IP�Ͷ˿�*/
	SOCKADDR_IN Dns;
	Dns.sin_family = AF_INET;
	Dns.sin_port = htons(PORT);
	Dns.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);

	char* temp = (char*)malloc(BUFFER_SIZE);	//�������
	char* ip = (char*)malloc(4);				//IP������
	int len = sizeof(client);
	while (1) {
		memset(buf, 0, BUFFER_SIZE);//��0���buf

		/*�ӿͻ��˽�����Ϣ������ʧ���������һ��ѭ��*/
		x = recvfrom(socketClient, buf, BUFFER_SIZE, 0, (struct sockaddr*)&client, &len);
		if (x < 0) {
			continue;
		}
		/*��������ֵ��temp������*/
		strcpy(temp, buf + sizeof(DNSHEADER) + 1);
		ToDomainName(temp);//Ԥ����

		int isFind = 0;
		/*��LRU������в�ѯ*/
		isFind = findDomainLRU(temp, ip);

		/*��ѯ�����������Ӧ����*/
		if (isFind == 1) {
			Respond(buf, ip, 0);
		}
		/*δ��ѯ������Ҫ�ȷ��ʱ��������ٷ����ϲ��dns���������в�ѯ*/
		else {//if(isFind == 1)
			/*LRUû�У���������в�ѯ*/
			isFind = findDomain(temp, ip);
			/*��ѯ�����������Ӧ����*/
			if (isFind == 1) {
				Respond(buf, ip, 0);
			}
			else {
				//FIFOδ���

				/*����ѯ��ԭ�ⲻ���ķ��͸�dns������*/
				sendto(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&Dns, sizeof(Dns));

				unsigned short id = *(unsigned short*)buf;//��ǰ����ֽ�
				unsigned short idtemp;
				int i = sizeof(Dns);
				unsigned int j;
				/*ֻ����Ӧ�����ѯ����id��ͬʱ��ֹͣ���գ�
				*���ڽ��յķ�ʽ�����˷����������������õĳ�ʱʱ��ʱ�����Զ�����һ��û�д𰸵���Ӧ��
				*���dns������֮ǰ���͵���Ӧ������Ƚ�����ô�ͻ���������ѯ�ʵĲ����ϣ��ͻ������������ʵ������������Ҫ����һ��ɸѡ
				*/
				do
				{
					j = recvfrom(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&Dns, &i);
					idtemp = *(unsigned short*)buf;
				} while (idtemp != id);
			}
		}
		/*����Ӧ��ԭ�ⲻ����ת�����ͻ��ˣ�����ʧ���򲻶��ط������ͳɹ�*/
		int tmp = 0;
		do
		{
			tmp = sendto(socketClient, buf, sizeof(buf), 0, (struct sockaddr*)&client, sizeof(client));
		} while (tmp < 0);
	}
}
/*������Ϣ�Ӽ���1*/
void dns_debug_1() {

}
/*������Ϣ�Ӽ���2*/
void dns_debug_2() {

}
int main(int argc, char** argv)
{
	printf("\nDNSRELAY, Version 0.1 Build:%s\n", __DATE__);
	printf("Usage: dnsrelay [-d|-dd] [<dns-server>] [<db-file>]\n\n");
	// init(argc,argv);
	if (argc == 1) {
		printf("������Ϣ�Ӽ���0 �޵�����Ϣ���\n");
		printf("ָ�����ַ�����Ϊ %s:53\n", SERVER_IP);
		printf("ʹ��Ĭ�������ļ� %s\n", LOCAL_FILE);
		openFile((char*)LOCAL_FILE, 0);
		dns_debug_0();
	}
	else if (argc == 4 && strcmp(argv[1], "-d") == 0) {
		printf("������Ϣ�Ӽ���1 �򵥵�����Ϣ���\n");
		printf("ָ�����ַ�����Ϊ %s:53\n", argv[2]);
		printf("ʹ��ָ�������ļ� %s\n", argv[3]);
		openFile(argv[3], 1);
		//dns_debug_1(argv[2], argv[3]);
	}
	else if (argc == 3 && strcmp(argv[1], "-dd") == 0) {
		printf("������Ϣ�Ӽ���2 ���ӵ�����Ϣ���\n");
		printf("ָ�����ַ�����Ϊ %s:53\n", argv[2]);
		printf("ʹ��Ĭ�������ļ� %s\n", LOCAL_FILE);
		openFile((char*)LOCAL_FILE, 2);
		//dns_debug_2(argv[2]);
	}
	else {
		printf("����������������������\n");
	}
	//printf("%d\n", domainIsExist("h0"));
	printf("hello\n");
	return 0;
}
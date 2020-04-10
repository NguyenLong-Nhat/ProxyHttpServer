#include"ProxySever.h"
#include "stdafx.h"
#include"stdafx.h"
#include"afxsock.h"
#include<stdio.h>
#include<iostream>
#include<string.h>
#include<vector>
#include<fstream>
#include<sstream>
#include<time.h>



using namespace std;


#ifdef _DEBUG
#define new DEBUG_NEW
#endif




SOCKET ToListen;

#define MAX_BUFF_SIZE 10000
#define PROXYPORT 8888
#define MAX_REQ_LEN 65535
#define MIN_REQ_LEN 4



struct ThrInfo
{
	SOCKET Sever;
	SOCKET Client;
	int SeverStatus;//1:open 0:close
	int ClientStatus;
	string url;
};
struct HTTPrequest
{
	string address;
	HANDLE handle;
	ThrInfo *CLIENT_SEVER;
	int port;
};
struct Cache_control
{
	int Cpublic = -1;
	int Cprivate = -1;
	int nocache = -1;
	int nostore = -1;
	int maxage = -1;
	int s_maxage = -1;
	int isetag = -1;
	string etag;
	tm lastmodified;
	int ismodified = 0;
	int mustrevalide = -1;
	tm expires;
	int isexpires = 0;
};
string Forbidden403 = "HTTP/1.0 403 Forbidden\r\n\Cache-Control: no-cache\r\n\Connection: close\r\n";
vector<string> Blacklist;
vector<string> Cacching;
void ReadFile()
{
	fstream File;
	File.open("blacklist.conf", ios::in);
	while (!File.eof())
	{
		string temp;
		getline(File, temp);
		if (temp.back() == '\n')
		{
			temp.pop_back();
		}
		Blacklist.push_back(temp);
	}
	//dua tat ca black list ve dang http://www.hostname de khong bi www.phimmoi.net khong tim duoc trong phimmoi.net
	for (int i = 0; i < Blacklist.size(); i++)
	{
		if (Blacklist[i].find("www.") == string::npos)
		{
			Blacklist[i] = "www." + Blacklist[i];
		}
		else
		{
			if (Blacklist[i].find("http://") == string::npos)
			{
				Blacklist[i] = "http://" + Blacklist[i];
			}
			else
			{
				if (Blacklist[i].find("http://www.") == string::npos)
				{
					Blacklist[i] = "http://www." + Blacklist[i];
				}
			}
		}
	}
	File.close();
}
bool CheckBlackList(string hostname)
{
	string Http = "http://";
	string www = "www.";
	if (Blacklist.size() > 0)
	{
		for (int i = 0; i < Blacklist.size(); i++)
		{
			if (Blacklist[i].find(hostname) != string::npos)
			{
				return true;
			}
		}
	}
	return false;
}
void Create_socket();
void ReadRequest(char *buff, vector<string> &Request_parse);
void GetHostSever(string &reqline, string &address, int &port, string &url);
UINT ConectToProxy(void* req);
UINT ConectToSever(void* req);
void setSock(sockaddr_in &a)
{
	a.sin_family = AF_INET;
	a.sin_port = 8888;
	a.sin_addr.s_addr = INADDR_ANY;
}
void Read_Date_time(tm &dt, string &str)
{
	string temp;
	temp = str.substr(0, 3);
	if (temp == "Sun")
		dt.tm_wday = 0;
	else
		if (temp == "Mon")
			dt.tm_wday = 1;
		else
			if (temp == "Tue")
				dt.tm_wday = 2;
			else
				if (temp == "Wes")
					dt.tm_wday = 3;
				else
					if (temp == "Thu")
						dt.tm_wday = 4;
					else
						if (temp == "Fri")
							dt.tm_wday = 5;
						else
							if (temp == "Sat")
								dt.tm_wday = 6;
	temp = str.substr(5, 7);
	dt.tm_mday = atoi(temp.c_str());
	temp = str.substr(8, 11);
	if (temp == "Jan")
		dt.tm_mon = 0;
	else
		if (temp == "Fer")
			dt.tm_mon = 1;
		else
			if (temp == "Mar")
				dt.tm_mon = 2;
			else
				if (temp == "Apr")
					dt.tm_mon = 3;
				else
					if (temp == "May")
						dt.tm_mon = 4;
					else
						if (temp == "Jun")
							dt.tm_mon = 5;
						else
							if (temp == "Jul")
								dt.tm_mon = 6;
							else
								if (temp == "Aug")
									dt.tm_mon = 7;
								else
									if (temp == "Sep")
										dt.tm_mon = 8;
									else
										if (temp == "Oct")
											dt.tm_mon = 9;
										else
											if (temp == "Nov")
												dt.tm_mon = 10;
											else
												if (temp == "Dec")
													dt.tm_mon = 11;
	temp = str.substr(12, 16);
	dt.tm_year = atoi(temp.c_str());
	temp = str.substr(17, 19);
	dt.tm_hour = atoi(temp.c_str());
	temp = str.substr(20, 22);
	dt.tm_min = atoi(temp.c_str());
	temp = str.substr(23, 25);
	dt.tm_sec = atoi(temp.c_str());
}
void ReadCache_control(vector<string> &Caching, Cache_control &cc)
{
	for (int i = 0; i < Caching.size(); i++)
	{
		if (Caching[i].find("Cache-Control:") != string::npos)
		{
			if (Caching[i].find("public") != string::npos)
			{
				cc.Cpublic = 1;
			}
			if (Caching[i].find("private") != string::npos)
			{
				cc.Cprivate = 1;
			}
			if (Caching[i].find("no-cache") != string::npos)
			{
				cc.nocache = 1;
			}
			if (Caching[i].find("no-store") != string::npos)
			{
				cc.nostore = 1;
			}
			if (Caching[i].find("must-revalidate") != string::npos)
			{
				cc.mustrevalide = 1;
			}
			if (Caching[i].find("max-age") != string::npos)
			{
				string temp;
				for (int j = Caching[i].find("max-age") + 8; j < Caching[i].length(); j++)
				{
					if (Caching[i].at(j) == ',' || Caching[i].at(j) == '\r')
					{
						cc.maxage = atoi(temp.c_str());
						j = Caching[i].length();
						break;
					}
					else
					{
						temp.push_back(Caching[i].at(j));
					}
				}

			}
			if (Caching[i].find("s-maxage") != string::npos)
			{
				string temp;
				for (int j = Caching[i].find("s-maxage") + 9; j < Caching[i].length(); j++)
				{
					if (Caching[i].at(j) == ',' || Caching[i].at(j) == '\r')
					{
						cc.s_maxage = atoi(temp.c_str());
						j = Caching[i].length();
						break;
					}
					else
					{
						temp.push_back(Caching[i].at(j));
					}
				}

			}

		}
		if (Caching[i].find("Last-Modified:") != string::npos)
		{
			int f = Caching[i].find("Last-Modified:") + 15;
			Read_Date_time(cc.lastmodified, Caching[i].substr(f, f + 29));
			cc.ismodified = 1;
		}
		if (Caching[i].find("Expires:") != string::npos)
		{
			int f = Caching[i].find("Expires:") + 9;
			Read_Date_time(cc.expires, Caching[i].substr(f, f + 29));
			cc.isexpires = 1;
		}
		if (Caching[i].find("Etag:") != string::npos)
		{
			int f = Caching[i].find(34);
			cc.etag = Caching[i].substr(f, Caching[i].find(34, f + 1));
			cc.isetag = 1;
		}

	}
}
bool checkCache(Cache_control &cc)
{
	if (cc.Cprivate > 0)
		return false;
	else
		if (cc.Cpublic <= 0)
		{
			if (cc.nocache > 0)
				return false;
			else
				if (cc.nostore > 0)
					return false;
				else
					if (cc.maxage >= 0)
						return true;
					else
						if (cc.s_maxage >= 0)
							return true;
						else
							if (cc.isetag > 0)
								return true;
							else
								if (cc.isexpires > 0)
									return true;
								else
									if (cc.ismodified > 0)
										return true;
									else
										return false;

		}

}

void Create_socket()
{
	sockaddr_in temp;
	SOCKET req;
	WSADATA wsaData;
	if (WSAStartup(0x202, &wsaData) != 0)
	{
		cout << "Fail To Creat Socket" << endl;
		WSACleanup();
		return;
	}
	//setSock(temp);
	temp.sin_family = AF_INET;
	temp.sin_addr.s_addr = INADDR_ANY;
	temp.sin_port = htons(8888);
	req = socket(AF_INET, SOCK_STREAM, 0);
	if (req == INVALID_SOCKET)
	{
		cout << "Error Creat Socket" << endl;
		WSACleanup();
		return;
	}
	if (bind(req, (sockaddr*)&temp, sizeof(temp)) != 0)
	{
		cout << "Bind Error" << endl;
		WSACleanup();
		return;
	}
	if (listen(req, 5) != 0)
	{
		cout << "Can't Listen" << endl;
		WSACleanup();
		return;
	}


	ToListen = req;



}
void Close_SeverProxy()
{
	closesocket(ToListen);
	WSACleanup();
}
void ListenFromClient(ThrInfo &CLIENT_SEVER, char*&buff, int &buff_len)
{
	int temp = recv(CLIENT_SEVER.Client, buff, buff_len, 0);
	if (temp <= 0)
	{
		cout << "ERROR RECV________________";
		if (CLIENT_SEVER.ClientStatus == 1)
		{
			CLIENT_SEVER.ClientStatus = 0;
			closesocket(CLIENT_SEVER.Client);
		}

	}
	if (temp >= MAX_BUFF_SIZE)
	{
		buff[temp - 1] = 0;

	}
	else
	{
		if (temp > 0)
		{
			buff[temp] = 0;
		}
		else
			buff[0] = 0;
	}
}
UINT ConectToProxy(void *req)
{

	//tao socket cua proxy va chap nhan ket noi
	SOCKET CLIENT;
	sockaddr_in addr;
	int addrlen = sizeof(addr);
	SOCKET ClientRQ = (SOCKET)req;
	CLIENT = accept(ClientRQ, (sockaddr*)&addr, &addrlen);
	//tao 1 thread khac nghe req khac de dong thoi xu ly
	AfxBeginThread(ConectToProxy, req);
	char buff[MAX_BUFF_SIZE];
	int buff_len;
	//dat thong tin
	ThrInfo CLIENT_SEVER;
	CLIENT_SEVER.Client = CLIENT;
	CLIENT_SEVER.ClientStatus = 1;
	CLIENT_SEVER.SeverStatus = 1;




	//bat dau xu ly request
	//nhan req
	//ListenFromClient(CLIENT_SEVER, buff, buff_len);
	int temp = recv(CLIENT_SEVER.Client, buff, MAX_BUFF_SIZE, 0);
	buff_len = temp;
	if (temp <= 0)
	{
		cout << "ERROR RECV________________" << endl;
		if (CLIENT_SEVER.ClientStatus == 1)
		{
			CLIENT_SEVER.ClientStatus = 0;
			closesocket(CLIENT_SEVER.Client);
			return -1;
		}

	}
	if (temp >= MAX_BUFF_SIZE)
	{
		buff[temp - 1] = 0;

	}
	else
	{
		if (temp > 0)
		{
			buff[temp] = 0;
		}
		else
			buff[0] = 0;
	}
	cout << buff;
	string buffer(buff);
	vector<string> Request_parse;
	string address; int port;
	ReadRequest(buff, Request_parse);
	GetHostSever(Request_parse[0], address, port, CLIENT_SEVER.url);
	cout << CLIENT_SEVER.url << endl;//chek url
	bool block = CheckBlackList(address);
	bool cachekey = -1;

	if (block == false)
	{
		ifstream File;
		string filename = "D:\cache" + CLIENT_SEVER.url + ".txt";
		File.open(filename);
		if (File.is_open())
		{
			cachekey = 1;
			string temp;
			while (!File.eof())
			{
				getline(File, temp);
				Cacching.push_back(temp);
			}
		}
		else
			cachekey = 0;
		File.close();
	}

	HTTPrequest request;
	request.address = address;
	request.handle = CreateEvent(NULL, TRUE, FALSE, NULL);
	request.port = port;
	request.CLIENT_SEVER = &CLIENT_SEVER;
	if (block == false)
	{
		CWinThread* SeverThread = AfxBeginThread(ConectToSever, (LPVOID)&request);
		WaitForSingleObject(request.handle, 10000);
		CloseHandle(request.handle);

		while (CLIENT_SEVER.ClientStatus == 1 && CLIENT_SEVER.SeverStatus == 1)
		{
			temp = send(CLIENT_SEVER.Sever, buffer.c_str(), buffer.size(), 0);
			if (temp == SOCKET_ERROR)
			{
				cout << "Send Error: " << GetLastError();
				CLIENT_SEVER.SeverStatus = 0;
			}
			continue;
			//ListenFromClient(CLIENT_SEVER, buff, buff_len);
			temp = recv(CLIENT_SEVER.Client, buff, buff_len, 0);
			if (temp <= 0)
			{
				cout << "ERROR RECV________________" << endl;
				if (CLIENT_SEVER.ClientStatus == 1)
				{
					CLIENT_SEVER.ClientStatus = 0;
					closesocket(CLIENT_SEVER.Client);
				}

			}
			if (temp >= MAX_BUFF_SIZE)
			{
				buff[temp - 1] = 0;

			}
			else
			{
				if (temp > 0)
				{
					buff[temp] = 0;
				}
				else
					buff[0] = 0;
			}
		}
		if (CLIENT_SEVER.SeverStatus == 1)
		{
			closesocket(CLIENT_SEVER.Sever);
			CLIENT_SEVER.SeverStatus = 0;
		}
		if (CLIENT_SEVER.ClientStatus == 1)
		{
			closesocket(CLIENT_SEVER.Client);
			CLIENT_SEVER.ClientStatus = 0;
		}
		WaitForSingleObject(SeverThread->m_hThread, 10000);

	}
	else
	{
		if (CLIENT_SEVER.ClientStatus == 1)
		{
			send(CLIENT_SEVER.Client, Forbidden403.c_str(), Forbidden403.size(), 0);
			CLIENT_SEVER.ClientStatus = 0;
			closesocket(CLIENT_SEVER.Client);
		}
	}
	return 0;
}
void ReadRequest(char* buff, vector<string> &request_parse)
{
	string temp = buff;
	int pos1 = 0; int pos2 = 0;
	for (int i = 0; i < temp.length(); i++)
	{
		if (temp.at(i) == '\r'&&temp.at(i + 1) == '\n')
		{

			pos1 = pos2;
			pos2 = i + 2;
			request_parse.push_back(temp.substr(pos1, pos2));
		}
	}

	//test cac cach cat request de lam catching
	/*while (1)
	{
		int pos1 = temp.find("\r\n");
		int pos2 = temp.find("\r\n\r\n");
		if (pos1 == pos2)
			break;
		else
		{
			request_parse.push_back(temp.substr(0, pos1));
			temp = temp.substr(pos1 + 2);
		}
	}*/
	/*fstream FILE;
	FILE.open("temp.dat", ios::in | ios::out);
	FILE << buff;
	FILE.seekp(0);

	while (!FILE.eof())
	{
		char temp[255];
		FILE.getline(temp,255);
		string tem2 = temp;
		request_parse.push_back(tem2);
	}*/




}
void GetHostSever(string &reqline, string &addr, int &port, string &url)
{
	if (reqline.size() > 0)
	{
		int pos1 = reqline.find("http://") + 7;
		int pos3 = reqline.find("HTTP/") - 4;
		if (pos1 - 7 != -1)
		{
			url = reqline.substr(pos1 - 7, pos3);
			addr = reqline.substr(pos1);
			pos1 = addr.find("/");
			if (pos1 != -1)
			{
				addr = addr.substr(0, pos1);
			}

			port = 80;
		}
	}
}
sockaddr_in* TrackingSever(string address, char* IPhost)
{
	int error_code;
	sockaddr_in *sever = NULL;
	if (address.size() > 0)
	{
		if (isalpha(address.at(0)))
		{

			addrinfo hints, *res = NULL;
			ZeroMemory(&hints, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			//vi day la http nen servicename la 80
			error_code = getaddrinfo(address.c_str(), "80", &hints, &res);
			if (error_code != 0)
			{
				cout << "ERROR GETADDRINFO CODE:" << gai_strerror(error_code) << endl;
				return NULL;
			}
			while (res->ai_next != NULL)
			{//lay res cuoi cung trong dslk
				res = res->ai_next;
			}
			sockaddr_in * temp = (sockaddr_in*)res->ai_addr;
			inet_ntop(res->ai_family, &temp->sin_addr, IPhost, 32);
			sever = (sockaddr_in*)res->ai_addr;
			long addr;

			inet_pton(AF_INET, IPhost, &addr);
			sever->sin_addr.s_addr = addr;
			sever->sin_port = htons(80);
			sever->sin_family = AF_INET;

		}
		else
		{
			long ipaddress;
			inet_pton(AF_INET, address.c_str(), &ipaddress);
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = ipaddress;

			if (getnameinfo((sockaddr*)&addr, sizeof(sockaddr), IPhost, NI_MAXHOST, NULL, NI_MAXSERV, NI_NUMERICSERV) != 0)
			{
				cout << "ERROR GETNAMEINFO CODE:" << WSAGetLastError() << endl;
				return NULL;
			}
			sever->sin_addr.s_addr = ipaddress;
			sever->sin_family = AF_INET;
			sever->sin_port = htons(80);
		}
		return sever;
	}

}
UINT ConectToSever(void *req)
{
	HTTPrequest *HttpRQ = (HTTPrequest*)req;
	string Host = HttpRQ->address;
	char IPaddress[32] = "";
	sockaddr_in *sever = NULL;
	sever = TrackingSever(Host, IPaddress);
	cout << IPaddress;//kiem tra ip
	if (sever == NULL)
	{
		cout << "ERROR IP DETEC" << endl;
		send(HttpRQ->CLIENT_SEVER->Client, Forbidden403.c_str(), Forbidden403.size(), 0);
		return -1;
	}
	char buff[MAX_BUFF_SIZE];

	SOCKET SSEVER;
	SSEVER = socket(AF_INET, SOCK_STREAM, 0);
	int temp;
	Cache_control c;
	ReadCache_control(Cacching, c);
	if (!(connect(SSEVER, (sockaddr*)sever, sizeof(sockaddr)) == 0))
	{
		cout << "CONNECT ERROR " << endl;
		send(HttpRQ->CLIENT_SEVER->Client, Forbidden403.c_str(), Forbidden403.size(), 0);
		return -1;
	}
	else
	{
		HttpRQ->CLIENT_SEVER->Sever = SSEVER;
		HttpRQ->CLIENT_SEVER->SeverStatus = 1;
		SetEvent(HttpRQ->handle);
		vector<string> Catching;
		while (HttpRQ->CLIENT_SEVER->ClientStatus == 1 && HttpRQ->CLIENT_SEVER->SeverStatus == 1)
		{
			temp = recv(HttpRQ->CLIENT_SEVER->Sever, buff, MAX_BUFF_SIZE, 0);
			if (temp == SOCKET_ERROR)
			{
				cout << "ERROR RECIEVE FROM SEVER " << GetLastError();
				closesocket(HttpRQ->CLIENT_SEVER->Sever);
				HttpRQ->CLIENT_SEVER->SeverStatus = 0;
				return -1;
			}
			if (temp == 0)
			{
				if (HttpRQ->CLIENT_SEVER->SeverStatus == 1)
				{
					closesocket(HttpRQ->CLIENT_SEVER->Sever);
					HttpRQ->CLIENT_SEVER->SeverStatus = 0;

				}
			}

			Catching.push_back(buff);

			//gui lai reponse
			temp = send(HttpRQ->CLIENT_SEVER->Client, buff, temp, 0);
			if (temp == SOCKET_ERROR)
			{
				cout << "SEND REPOSNE ERROR" << GetLastError();
				closesocket(HttpRQ->CLIENT_SEVER->Client);
				HttpRQ->CLIENT_SEVER->ClientStatus = 0;
				break;
			}
			if (temp >= MAX_BUFF_SIZE)
			{
				buff[temp - 1] = 0;
			}
			else
			{
				buff[temp] = 0;
			}
			ZeroMemory(buff, MAX_BUFF_SIZE);


		}
		Cache_control cc;
		ReadCache_control(Catching, cc);
		if (checkCache(cc))
		{
			ofstream File;
			string filename = "D:\cache" + HttpRQ->CLIENT_SEVER->url + ".txt";
			File.open(filename);
			for (int i = 0; i < Catching.size(); i++)
			{
				File << Catching[i];
			}
			File.close();

		}


		if (HttpRQ->CLIENT_SEVER->SeverStatus == 1)
		{
			closesocket(HttpRQ->CLIENT_SEVER->Sever);
			HttpRQ->CLIENT_SEVER->SeverStatus = 0;

		}
		if (HttpRQ->CLIENT_SEVER->ClientStatus == 1)
		{
			closesocket(HttpRQ->CLIENT_SEVER->Client);
			HttpRQ->CLIENT_SEVER->ClientStatus = 0;

		}
		cout << "reposnt:" << endl;
		for (int i = 0; i < Catching.size(); i++)
		{
			cout << Catching[i] << endl;
		}

	}

	return 0;
}

int main()
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(nullptr);

	if (hModule != nullptr)
	{
		// initialize MFC and print and error on failure
		if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
		{
			// TODO: change error code to suit your needs
			wprintf(L"Fatal Error: MFC initialization failed\n");
			nRetCode = 1;
		}
		else
		{
			//goi ham doc black list de doc file 1 lan, khong phai doc nhieu lan
			ReadFile();
			//khoi tao 1 socket de ket noi toi proxy
			Create_socket();
			//ket noi toi proxy qua socket Tolisten
			AfxBeginThread(ConectToProxy, (LPVOID)ToListen);
			while (1)
			{
				Sleep(1000);
			}
			Close_SeverProxy();

		}
	}
	else
	{
		// TODO: change error code to suit your needs
		wprintf(L"Fatal Error: GetModuleHandle failed\n");
		nRetCode = 1;
	}

	return nRetCode;
}


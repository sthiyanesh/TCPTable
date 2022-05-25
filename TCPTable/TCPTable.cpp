// TCPTable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// Need to link with Iphlpapi.lib and Ws2_32.lib
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include<string>
#include <iostream>
#include<fstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)
using namespace std;

struct process {
    int Pid;
    string Pname;
    string LocalAddress;
    int LocalPort;
    string RemoteAddress;
    int RemotePort;
    int StateID;
    string StateName;
    unsigned long long int DataByteIn;
    unsigned long long int DataByteOut;
    unsigned long long int TotalByte;
    int sflag = 0;
};

struct diffdata {
    string Pname;
    unsigned long long int DataByteIn;
    unsigned long long int DataByteOut;
    unsigned long long int TotalByte;
};

string ProcessIdToName(DWORD processId)
{
    string ret;
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,
        processId /* This is the PID, you can find one from windows task manager */
    );
    if (handle)
    {
        DWORD buffSize = 1024;
        CHAR buffer[1024];
        if (QueryFullProcessImageNameA(handle, 0, buffer, &buffSize))
        {
            ret = buffer;
        }
        else
        {
            return "Error GetModuleBaseNameA : "+GetLastError();
        }
        CloseHandle(handle);
    }
    else
    {
        return "Error OpenProcess : "+GetLastError();
    }
    return ret;
}

vector<process> getData() {
    vector<process> a;

    vector<unsigned char> buffer;
    DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
    DWORD dwRetValue = 0;

    char szLocalAddr[128];
    char szRemoteAddr[128];

    struct in_addr IpAddr;

    do {
        buffer.resize(dwSize, 0);
        dwRetValue = GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    } while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);
    if (dwRetValue == ERROR_SUCCESS)
    {
        PMIB_TCPTABLE_OWNER_PID ptTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        cout << "Number of Entries: " << ptTable->dwNumEntries << endl << endl;
        //cout << "TCP\tPID\tSTATE\t\tLocal Addr\tLocal Port\tRemote Address\tRemote Port\tProcess Name";
        for (DWORD i = 0; i < ptTable->dwNumEntries; i++) {
            process p;
            DWORD pid = ptTable->table[i].dwOwningPid;
            IpAddr.S_un.S_addr = (u_long)ptTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr = (u_long)ptTable->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
            string pname = ProcessIdToName(pid);
            printf("\n%d\t%d\t%ld - ", i, pid,
                ptTable->table[i].dwState);
            cout << pname;
            string Statename;
            switch (ptTable->table[i].dwState) {
            case MIB_TCP_STATE_CLOSED:
                Statename = "CLOSED";
                break;
            case MIB_TCP_STATE_LISTEN:
                Statename = "LISTEN";
                break;
            case MIB_TCP_STATE_SYN_SENT:
                Statename = "SYN-SENT";
                break;
            case MIB_TCP_STATE_SYN_RCVD:
                Statename = "SYN-RECEIVED";
                break;
            case MIB_TCP_STATE_ESTAB:
                Statename = "ESTABLISHED";
                break;
            case MIB_TCP_STATE_FIN_WAIT1:
                Statename = "FIN-WAIT-1";
                break;
            case MIB_TCP_STATE_FIN_WAIT2:
                Statename = "FIN-WAIT-2";
                break;
            case MIB_TCP_STATE_CLOSE_WAIT:
                Statename = "CLOSE-WAIT";
                break;
            case MIB_TCP_STATE_CLOSING:
                Statename = "CLOSING";
                break;
            case MIB_TCP_STATE_LAST_ACK:
                Statename = "LAST-ACK";
                break;
            case MIB_TCP_STATE_TIME_WAIT:
                Statename = "TIME-WAIT";
                break;
            case MIB_TCP_STATE_DELETE_TCB:
                Statename = "DELETE-TCB";
                break;
            default:
                Statename = "UNKNOWN dwState value";
                break;
            }

            /*printf("\t%s", szLocalAddr);
            printf(" \t%d",
                ntohs((u_short)ptTable->table[i].dwLocalPort));
            printf("\t\t%s", szRemoteAddr);
            printf("\t%d\t",
                ntohs((u_short)ptTable->table[i].dwRemotePort));
            */

            p.Pid = pid;
            p.Pname = pname;
            p.LocalAddress = szLocalAddr;
            p.RemoteAddress = szRemoteAddr;
            p.LocalPort = ptTable->table[i].dwLocalPort;
            p.RemotePort = ptTable->table[i].dwRemotePort;
            p.StateID = ptTable->table[i].dwState;
            p.StateName = Statename;

            MIB_TCPROW row;
            row.dwLocalAddr = ptTable->table[i].dwLocalAddr;
            row.dwLocalPort = ptTable->table[i].dwLocalPort;
            row.dwRemoteAddr = ptTable->table[i].dwRemoteAddr;
            row.dwRemotePort = ptTable->table[i].dwRemotePort;
            row.dwState = ptTable->table[i].dwState;
            void* processRow = &row;

            if (row.dwRemoteAddr != 0)
            {
                ULONG rosSize = 0, rodSize = 0;
                ULONG winStatus;
                PUCHAR ros = NULL, rod = NULL;
                rodSize = sizeof(TCP_ESTATS_DATA_ROD_v0);
                PTCP_ESTATS_DATA_ROD_v0 dataRod = { 0 };

                if (rosSize != 0) {
                    ros = (PUCHAR)malloc(rosSize);
                    if (ros == NULL) {
                        wprintf(L"\nOut of memory");
                        return a;
                    }
                    else
                        memset(ros, 0, rosSize); // zero the buffer
                }
                if (rodSize != 0) {
                    rod = (PUCHAR)malloc(rodSize);
                    if (rod == NULL) {
                        free(ros);
                        wprintf(L"\nOut of memory");
                        return a;
                    }
                    else
                        memset(rod, 0, rodSize); // zero the buffer
                }

                winStatus = GetPerTcpConnectionEStats((PMIB_TCPROW)&row, TcpConnectionEstatsData, NULL, 0, 0, ros, 0, rosSize, rod, 0, rodSize);

                dataRod = (PTCP_ESTATS_DATA_ROD_v0)rod;

                cout << "\nDataBytesIn:" << dataRod->DataBytesIn << "\n";
                cout << "\nDataBytesOut:" << dataRod->DataBytesOut << "\n";

                p.DataByteIn = dataRod->DataBytesIn;
                p.DataByteOut = dataRod->DataBytesOut;

                PTCP_ESTATS_BANDWIDTH_ROD_v0 bandwidthRod = { 0 };

                rodSize = sizeof(TCP_ESTATS_BANDWIDTH_ROD_v0);
                if (rodSize != 0) {
                    rod = (PUCHAR)malloc(rodSize);
                    if (rod == NULL) {
                        free(ros);
                        wprintf(L"\nOut of memory");
                        return a;
                    }
                    else
                        memset(rod, 0, rodSize); // zero the buffer
                }

                winStatus = GetPerTcpConnectionEStats((PMIB_TCPROW)&row, TcpConnectionEstatsBandwidth, NULL, 0, 0, ros, 0, rosSize, rod, 0, rodSize);

                bandwidthRod = (PTCP_ESTATS_BANDWIDTH_ROD_v0)rod;

                //cout << "\nOutboundBandwidth:" << bandwidthRod->OutboundBandwidth << "\n";
                //cout << "\nInboundBandwidth:" << bandwidthRod->InboundBandwidth << "\n";
                int flag = 0;
                for (int i = 0;i < a.size();i++) {
                    if (a[i].Pid == p.Pid) {
                        a[i].DataByteIn += p.DataByteIn;
                        a[i].DataByteOut += p.DataByteOut;
                        flag = 1;
                        break;
                    }
                }
                if (flag == 0) {
                    a.push_back(p);
                }

            }
        }
    }

    return a;
}

int main() {
    vector<process> a = getData();
    for (int i = 0;i < 3;i++) {
        cout << "thiyanesh";
        Sleep(1000 * 60 * 2);
        cout << "Time Out";
        vector<process> b = getData();
        vector<diffdata> d;
        
        // To find the Difference After 5 Mins
        for (int i = 0;i < a.size();i++) {
            for (int j = 0;j < b.size();j++) {
                if (a[i].Pname.substr(0, 5) != "Error" && b[j].Pname.substr(0, 5) != "Error" && a[i].Pname == b[j].Pname && a[i].DataByteIn <= b[j].DataByteIn && a[i].DataByteOut <=b[j].DataByteOut) {
                    diffdata c;
                    c.Pname = a[i].Pname;
                    cout << "\n" << a[i].Pid << a[i].Pname;
                    cout << "\n" << b[j].DataByteIn;
                    cout << "\n" << a[i].DataByteIn;
                    c.DataByteIn = b[j].DataByteIn - a[i].DataByteIn;
                    c.DataByteOut = b[j].DataByteOut - a[i].DataByteOut;
                    c.TotalByte = c.DataByteIn + c.DataByteOut;
                    cout << "\n" << c.DataByteIn;
                    cout << "\n" << c.DataByteOut;
                    cout << "\n" << c.TotalByte << "\n";
                    //cout << "\nProcess Name:" << a[i].Pname << "\nDataByteIn:" << b[j].DataByteIn << "\nDataByteOut:" << b[j].DataByteOut << endl;
                    d.push_back(c);
                }
            }
        }
        a = b;

        // Sorting based on Total Bytes.
        for (int i = 0;i < d.size();i++) {
            for (int j = 0;j < d.size()-1;j++) {
                if (d[j].TotalByte < d[j + 1].TotalByte) {
                    diffdata p = d[j];
                    d[j] = d[j+1];
                    d[j + 1] = p;
                }
            }
        }
        
        //Getting Content of File.
        string content = "After 5 mins\n{";
        int s = (d.size() < 10) ? d.size() : 10;
        for (int i = 0;i < s;i++) {
            content += "\n\t\"" + d[i].Pname + "\":{\n\t\t\"bytein\":" + (to_string(d[i].DataByteIn)) + ",\n\t\t\"byteout\":" + to_string(d[i].DataByteOut) + ",\n\t\t\"totalbytes\":" + to_string(d[i].TotalByte) + "\n\t},";
        }
        cout << content;
        // Writing to File.
        

    }
    cin.get();
    return 0;
}// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

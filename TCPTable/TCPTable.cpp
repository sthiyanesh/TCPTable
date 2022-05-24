// TCPTable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// Need to link with Iphlpapi.lib and Ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"psapi")
#pragma comment(lib,"iphlpapi")
#pragma comment(lib,"wsock32")
#pragma warning(disable: 4996)
#include <windows.h>
#include <winsock.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include "psapi.h"
using namespace std;

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
            printf("Error GetModuleBaseNameA : %lu", GetLastError());
        }
        CloseHandle(handle);
    }
    else
    {
        printf("Error OpenProcess : %lu", GetLastError());
    }
    return ret;
}

int main() {
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
        cout << "TCP\tPID\tSTATE\t\tLocal Addr\tLocal Port\tRemote Address\tRemote Port\tProcess Name";
        for (DWORD i = 0; i < ptTable->dwNumEntries; i++) {
            DWORD pid = ptTable->table[i].dwOwningPid;
            IpAddr.S_un.S_addr = (u_long)ptTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr = (u_long)ptTable->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
            string pname = ProcessIdToName(pid);
            printf("\n%d\t%d\t%ld - ", i,pid,
                ptTable->table[i].dwState);
            switch (ptTable->table[i].dwState) {
            case MIB_TCP_STATE_CLOSED:
                printf("CLOSED");
                break;
            case MIB_TCP_STATE_LISTEN:
                printf("LISTEN");
                break;
            case MIB_TCP_STATE_SYN_SENT:
                printf("SYN-SENT");
                break;
            case MIB_TCP_STATE_SYN_RCVD:
                printf("SYN-RECEIVED");
                break;
            case MIB_TCP_STATE_ESTAB:
                printf("ESTABLISHED");
                break;
            case MIB_TCP_STATE_FIN_WAIT1:
                printf("FIN-WAIT-1");
                break;
            case MIB_TCP_STATE_FIN_WAIT2:
                printf("FIN-WAIT-2");
                break;
            case MIB_TCP_STATE_CLOSE_WAIT:
                printf("CLOSE-WAIT");
                break;
            case MIB_TCP_STATE_CLOSING:
                printf("CLOSING");
                break;
            case MIB_TCP_STATE_LAST_ACK:
                printf("LAST-ACK");
                break;
            case MIB_TCP_STATE_TIME_WAIT:
                printf("TIME-WAIT");
                break;
            case MIB_TCP_STATE_DELETE_TCB:
                printf("DELETE-TCB");
                break;
            default:
                printf("UNKNOWN dwState value");
                break;
            }
            printf("\t%s", szLocalAddr);
            printf(" \t%d",
                ntohs((u_short)ptTable->table[i].dwLocalPort));
            printf("\t\t%s", szRemoteAddr);
            printf("\t%d\t",
                ntohs((u_short)ptTable->table[i].dwRemotePort));
            cout << "\t" << pname;

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
                        return 0;
                    }
                    else
                        memset(ros, 0, rosSize); // zero the buffer
                }
                if (rodSize != 0) {
                    rod = (PUCHAR)malloc(rodSize);
                    if (rod == NULL) {
                        free(ros);
                        wprintf(L"\nOut of memory");
                        return 0;
                    }
                    else
                        memset(rod, 0, rodSize); // zero the buffer
                }

                winStatus = GetPerTcpConnectionEStats((PMIB_TCPROW)&row, TcpConnectionEstatsData, NULL, 0, 0, ros, 0, rosSize, rod, 0, rodSize);

                dataRod = (PTCP_ESTATS_DATA_ROD_v0)rod;

                cout<<dataRod->DataBytesIn;
                cout<<dataRod->DataBytesOut;

                PTCP_ESTATS_BANDWIDTH_ROD_v0 bandwidthRod = { 0 };

                rodSize = sizeof(TCP_ESTATS_BANDWIDTH_ROD_v0);
                if (rodSize != 0) {
                    rod = (PUCHAR)malloc(rodSize);
                    if (rod == NULL) {
                        free(ros);
                        wprintf(L"\nOut of memory");
                        return 0;
                    }
                    else
                        memset(rod, 0, rodSize); // zero the buffer
                }

                winStatus = GetPerTcpConnectionEStats((PMIB_TCPROW)&row, TcpConnectionEstatsBandwidth, NULL, 0, 0, ros, 0, rosSize, rod, 0, rodSize);

                bandwidthRod = (PTCP_ESTATS_BANDWIDTH_ROD_v0)rod;
                cout << bandwidthRod->OutboundBandwidth;
                cout << bandwidthRod->InboundBandwidth;

            }
        }
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

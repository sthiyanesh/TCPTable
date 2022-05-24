// TCPTable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// Need to link with Iphlpapi.lib and Ws2_32.lib
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
using namespace std;

void main() {
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
        cout << "TCP\tPID\tSTATE\t\tLocal Addr\tLocal Port\tRemote Address\tRemote Port";
        for (DWORD i = 0; i < ptTable->dwNumEntries; i++) {
            DWORD pid = ptTable->table[i].dwOwningPid;
            IpAddr.S_un.S_addr = (u_long)ptTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr = (u_long)ptTable->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));

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
            printf("\t%d",
                ntohs((u_short)ptTable->table[i].dwRemotePort));
        }
    }
    cin.get();
}// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

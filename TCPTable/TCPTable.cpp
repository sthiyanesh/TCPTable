// TCPTable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// Need to link with Iphlpapi.lib and Ws2_32.lib
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */

int main()
{

    // Declare and initialize variables
    PMIB_TCPTABLE pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    char szLocalAddr[128];
    char szRemoteAddr[128];

    struct in_addr IpAddr;

    int i;

    pTcpTable = (MIB_TCPTABLE*)MALLOC(sizeof(MIB_TCPTABLE));
    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    dwSize = sizeof(MIB_TCPTABLE);
    // Make an initial call to GetTcpTable to
    // get the necessary size into the dwSize variable
    if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) ==
        ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE*)MALLOC(dwSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }
    }
    // Make a second call to GetTcpTable to get
    // the actual data we require
    if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        printf("\tNumber of entries: %d\n", (int)pTcpTable->dwNumEntries);
        printf("TCP\tSTATE\t\tLocal Addr\tLocal Port\tRemote Address\tRemote Port");
        for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));

            printf("\n%d\t%ld - ", i,
                pTcpTable->table[i].dwState);
            switch (pTcpTable->table[i].dwState) {
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
                ntohs((u_short)pTcpTable->table[i].dwLocalPort));
            printf("\t%s", szRemoteAddr);
            printf("\t%d",
                ntohs((u_short)pTcpTable->table[i].dwRemotePort));
        }
    }
    else {
        printf("\tGetTcpTable failed with %d\n", dwRetVal);
        FREE(pTcpTable);
        return 1;
    }

    if (pTcpTable != NULL) {
        FREE(pTcpTable);
        pTcpTable = NULL;
    }

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

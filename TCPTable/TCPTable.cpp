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

char* dupcat(const char* s1, ...) {
    int len;
    char* p, * q, * sn;
    va_list ap;

    len = strlen(s1);
    va_start(ap, s1);
    while (1) {
        sn = va_arg(ap, char*);
        if (!sn)
            break;
        len += strlen(sn);
    }
    va_end(ap);

    p = new char[len + 1];
    strcpy(p, s1);
    q = p + strlen(p);

    va_start(ap, s1);
    while (1) {
        sn = va_arg(ap, char*);
        if (!sn)
            break;
        strcpy(q, sn);
        q += strlen(q);
    }
    va_end(ap);

    return p;
}

/*string processName(DWORD id) {
    HANDLE processHandle = NULL;
    char filename[MAX_PATH];
    char* ret;

    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);
    if (processHandle != NULL) {
        if (GetModuleBaseName(processHandle, NULL, filename, sizeof(filename)) == 0) {
            return "Failed to get module filename.";
        }
        else {
            ret = dupcat(filename, 0);
            return ret;
        }
        CloseHandle(processHandle);
    }
    return "Failed to open process.";
}*/

char* dwordToString(DWORD id) {
    char aux[10];
    unsigned long parts[] = { (id & 0xff),(id >> 8) & 0xff,(id >> 16) & 0xff,(id >> 24) & 0xff };
    char* ret = dupcat(ultoa(parts[0], aux, 10), ".", 0);
    for (int i = 1;i < 4;i++) {
        if (i < 3)
            ret = dupcat(ret, ultoa(parts[i], aux, 10), ".", 0);
        else
            ret = dupcat(ret, ultoa(parts[i], aux, 10), 0);
    }
    return ret;
}

void main() {
    vector<unsigned char> buffer;
    DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
    DWORD dwRetValue = 0;

    do {
        buffer.resize(dwSize, 0);
        dwRetValue = GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    } while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);
    if (dwRetValue == ERROR_SUCCESS)
    {
        PMIB_TCPTABLE_OWNER_PID ptTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        cout << "Number of Entries: " << ptTable->dwNumEntries << endl << endl;
        for (DWORD i = 0; i < ptTable->dwNumEntries; i++) {
            DWORD pid = ptTable->table[i].dwOwningPid;
            cout << "PID: " << pid << endl;
            //cout << "Name: " << processName(ptTable->table[i].dwOwningPid) << endl;
            cout << "State: " << ptTable->table[i].dwState << endl;
            cout << "Local: "
                << dwordToString(ptTable->table[i].dwLocalAddr)
                << ":"
                << htons((unsigned short)ptTable->table[i].dwLocalPort)
                << endl;

            cout << "Remote: "
                << dwordToString(ptTable->table[i].dwRemoteAddr)
                << ":"
                << htons((unsigned short)ptTable->table[i].dwRemotePort)
                << endl;

            cout << endl;
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

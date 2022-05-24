#include "stdafx.h"
#include "NetworkPerformanceScanner.h"
using namespace std;


NetworkPerformanceScanner::NetworkPerformanceScanner()
{

}


NetworkPerformanceScanner::~NetworkPerformanceScanner()
{
}

// TODO - implement TCP v6, UDP
std::vector<NetworkPerformanceItem> NetworkPerformanceScanner::ScanNetworkPerformance(int pass)
{

    std::vector<unsigned char> buffer;
    DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
    DWORD dwRetValue = 0;
    vector<NetworkPerformanceItem> networkPerformanceItems;

    // get local computer time with timezone offset
    auto time = std::time(nullptr);
    std::ostringstream timeStream;
    timeStream << std::put_time(std::localtime(&time), "%F %T%z");
    string collectionTime = timeStream.str();

    // repeat till buffer is big enough
    do
    {
        buffer.resize(dwSize, 0);
        dwRetValue = GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    } while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);

    if (dwRetValue == ERROR_SUCCESS)
    {
        // good case

        // cast to access element values
        PMIB_TCPTABLE_OWNER_PID ptTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

        cout << "Number of Entries: " << ptTable->dwNumEntries << endl << endl;


        // caution: array starts with index 0, count starts by 1
        for (DWORD i = 0; i < ptTable->dwNumEntries; i++)
        {
            NetworkPerformanceItem networkPerformanceItem;

            networkPerformanceItem.ProcessId = ptTable->table[i].dwOwningPid;
            networkPerformanceItem.State = ptTable->table[i].dwState;

            cout << "PID: " << ptTable->table[i].dwOwningPid << endl;
            cout << "State: " << ptTable->table[i].dwState << endl;

            std::ostringstream localStream;
            localStream << (ptTable->table[i].dwLocalAddr & 0xFF)
                << "."
                << ((ptTable->table[i].dwLocalAddr >> 8) & 0xFF)
                << "."
                << ((ptTable->table[i].dwLocalAddr >> 16) & 0xFF)
                << "."
                << ((ptTable->table[i].dwLocalAddr >> 24) & 0xFF)
                << ":"
                << htons((unsigned short)ptTable->table[i].dwLocalPort);
            networkPerformanceItem.LocalAddress = localStream.str();
            networkPerformanceItem.LocalPort = ptTable->table[i].dwLocalPort;

            std::ostringstream remoteStream;
            remoteStream << (ptTable->table[i].dwRemoteAddr & 0xFF)
                << "."
                << ((ptTable->table[i].dwRemoteAddr >> 8) & 0xFF)
                << "."
                << ((ptTable->table[i].dwRemoteAddr >> 16) & 0xFF)
                << "."
                << ((ptTable->table[i].dwRemoteAddr >> 24) & 0xFF)
                << ":"
                << htons((unsigned short)ptTable->table[i].dwRemotePort);
            networkPerformanceItem.RemoteAddress = remoteStream.str();
            networkPerformanceItem.RemotePort = ptTable->table[i].dwRemotePort;

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
                        return networkPerformanceItems;
                    }
                    else
                        memset(ros, 0, rosSize); // zero the buffer
                }
                if (rodSize != 0) {
                    rod = (PUCHAR)malloc(rodSize);
                    if (rod == NULL) {
                        free(ros);
                        wprintf(L"\nOut of memory");
                        return networkPerformanceItems;
                    }
                    else
                        memset(rod, 0, rodSize); // zero the buffer
                }

                winStatus = GetPerTcpConnectionEStats((PMIB_TCPROW)&row, TcpConnectionEstatsData, NULL, 0, 0, ros, 0, rosSize, rod, 0, rodSize);

                dataRod = (PTCP_ESTATS_DATA_ROD_v0)rod;

                networkPerformanceItem.BytesIn = dataRod->DataBytesIn;
                networkPerformanceItem.BytesOut = dataRod->DataBytesOut;

                PTCP_ESTATS_BANDWIDTH_ROD_v0 bandwidthRod = { 0 };

                rodSize = sizeof(TCP_ESTATS_BANDWIDTH_ROD_v0);
                if (rodSize != 0) {
                    rod = (PUCHAR)malloc(rodSize);
                    if (rod == NULL) {
                        free(ros);
                        wprintf(L"\nOut of memory");
                        return networkPerformanceItems;
                    }
                    else
                        memset(rod, 0, rodSize); // zero the buffer
                }

                winStatus = GetPerTcpConnectionEStats((PMIB_TCPROW)&row, TcpConnectionEstatsBandwidth, NULL, 0, 0, ros, 0, rosSize, rod, 0, rodSize);

                bandwidthRod = (PTCP_ESTATS_BANDWIDTH_ROD_v0)rod;
                networkPerformanceItem.OutboundBandwidth = bandwidthRod->OutboundBandwidth;
                networkPerformanceItem.InboundBandwidth = bandwidthRod->InboundBandwidth;

            }
            networkPerformanceItem.Pass = pass;
            networkPerformanceItem.CollectionTime = collectionTime;
            networkPerformanceItems.push_back(networkPerformanceItem);
        }
    }
    else
    {
        // bad case, do some sh*t here
    }

    return networkPerformanceItems;
}

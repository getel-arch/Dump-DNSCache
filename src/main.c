#include <windows.h>
#include <stdio.h>
#include <windns.h>
#include <time.h>

// Undocumented DNS cache entry structure and function
typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY *pNext;
    PWSTR pszName;
    WORD wType;
    WORD wDataLength;
    DWORD dwFlags;
    DWORD dwTtl;
} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;

// Use DnsGetCacheDataTableEx and DnsFree
DWORD WINAPI DnsGetCacheDataTableEx(DWORD, PDNS_CACHE_ENTRY*);

#pragma comment(lib, "dnsapi.lib")

int main(int argc, char *argv[]) {
    PDNS_CACHE_ENTRY pEntry = NULL;
    PDNS_CACHE_ENTRY pCurrent = NULL;
    PDNS_CACHE_ENTRY pNext = NULL;
    FILE *out = stdout;
    int csv_mode = 0;

    // Check for optional CSV file parameter
    if (argc > 1) {
        out = fopen(argv[1], "w");
        if (!out) {
            printf("Failed to open file: %s\n", argv[1]);
            return 1;
        }
        csv_mode = 1;
    }

    // Get the DNS cache table using DnsGetCacheDataTableEx
    DWORD status = DnsGetCacheDataTableEx(1, &pEntry);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ACCESS_DENIED) {
            fprintf(out, "Failed to get DNS cache table: Access denied. Please run as Administrator.\n");
        } else {
            fprintf(out, "Failed to get DNS cache table. Error code: %lu\n", status);
        }
        if (csv_mode) fclose(out);
        return 1;
    }

    time_t now = time(NULL);

    if (csv_mode) {
        // Print CSV header
        fprintf(out, "Name,Type,DataLength,Flags,TTL,Data\n");
    } else {
        // Print human-readable header
        printf("DNS Cache Entries:\n");
        printf("%-40s %-10s %-12s %-10s %-10s %-s\n", "Name", "Type", "DataLen", "Flags", "TTL", "Data");
    }

    pCurrent = pEntry;
    while (pCurrent) {
        pNext = pCurrent->pNext;
        DWORD ttl = (pCurrent->dwTtl > now) ? (pCurrent->dwTtl - now) : 0;

        // Prepare buffer for record data
        char data_buf[256] = "";
        if (pCurrent->wDataLength > 0) {
            DNS_RECORD *pDnsRecord = NULL;
            DNS_STATUS dnsStatus = DnsQuery_W(
                pCurrent->pszName,
                pCurrent->wType,
                DNS_QUERY_NO_WIRE_QUERY | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT,
                NULL,
                &pDnsRecord,
                NULL
            );
            if (dnsStatus == ERROR_SUCCESS && pDnsRecord) {
                DNS_RECORD *rec = pDnsRecord;
                // Only print the first record for brevity
                switch (rec->wType) {
                    case DNS_TYPE_A:
                        snprintf(data_buf, sizeof(data_buf), "%u.%u.%u.%u",
                            (rec->Data.A.IpAddress) & 0xFF,
                            (rec->Data.A.IpAddress >> 8) & 0xFF,
                            (rec->Data.A.IpAddress >> 16) & 0xFF,
                            (rec->Data.A.IpAddress >> 24) & 0xFF
                        );
                        break;
                    case DNS_TYPE_AAAA: {
                        char ipv6[64];
                        DWORD ipv6len = sizeof(ipv6);
                        if (WSAAddressToStringA((LPSOCKADDR)&rec->Data.AAAA.Ip6Address, sizeof(rec->Data.AAAA.Ip6Address), NULL, ipv6, &ipv6len) == 0) {
                            snprintf(data_buf, sizeof(data_buf), "%s", ipv6);
                        } else {
                            snprintf(data_buf, sizeof(data_buf), "<IPv6>");
                        }
                        break;
                    }
                    case DNS_TYPE_PTR:
                        WideCharToMultiByte(CP_UTF8, 0, rec->Data.PTR.pNameHost, -1, data_buf, sizeof(data_buf), NULL, NULL);
                        break;
                    default:
                        snprintf(data_buf, sizeof(data_buf), "<type %u>", rec->wType);
                        break;
                }
                DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
            }
        }

        if (csv_mode) {
            // Print CSV row
            fprintf(out, "\"%ws\",%u,%u,0x%08lx,%lu,\"%s\"\n",
                pCurrent->pszName,
                pCurrent->wType,
                pCurrent->wDataLength,
                (unsigned long)pCurrent->dwFlags,
                ttl,
                data_buf
            );
        } else {
            // Print human-readable row
            printf("%-40ws %-10u %-12u 0x%08lx %-10lu %s\n",
                pCurrent->pszName,
                pCurrent->wType,
                pCurrent->wDataLength,
                (unsigned long)pCurrent->dwFlags,
                ttl,
                data_buf
            );
        }
        // Free pszName if allocated
        if (pCurrent->pszName) {
            DnsFree(pCurrent->pszName, 0);
        }
        DnsFree(pCurrent, 0);
        pCurrent = pNext;
    }

    if (csv_mode) fclose(out);

    return 0;
}


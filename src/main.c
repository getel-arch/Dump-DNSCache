#include <windows.h>
#include <stdio.h>
#include <windns.h>

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
VOID WINAPI DnsFree(PVOID, DWORD);

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

    if (csv_mode) {
        // Print CSV header
        fprintf(out, "Name,Type,TTL\n");
    } else {
        // Print human-readable header
        printf("DNS Cache Entries:\n");
        printf("%-40s %-10s %-10s\n", "Name", "Type", "TTL");
    }

    pCurrent = pEntry;
    while (pCurrent) {
        pNext = pCurrent->pNext;
        if (csv_mode) {
            // Print CSV row
            fprintf(out, "\"%ws\",%u,%u\n", pCurrent->pszName, pCurrent->wType, pCurrent->dwTtl);
        } else {
            // Print human-readable row
            printf("%-40ws %-10u %-10u\n", pCurrent->pszName, pCurrent->wType, pCurrent->dwTtl);
        }
        DnsFree(pCurrent, 0);
        pCurrent = pNext;
    }

    if (csv_mode) fclose(out);

    return 0;
}


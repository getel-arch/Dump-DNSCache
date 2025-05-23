#include <windows.h>
#include <stdio.h>
#include <dnsapi.h>

#pragma comment(lib, "dnsapi.lib")

int main(int argc, char *argv[]) {
    PDNS_CACHE_ENTRY pEntry = NULL;
    PDNS_CACHE_ENTRY pCurrent = NULL;
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

    // Get the DNS cache table
    if (DnsGetCacheDataTable(&pEntry) != ERROR_SUCCESS) {
        fprintf(out, "Failed to get DNS cache table.\n");
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
        if (csv_mode) {
            // Print CSV row
            fprintf(out, "\"%s\",%u,%u\n", pCurrent->pszName, pCurrent->wType, pCurrent->dwTtl);
        } else {
            // Print human-readable row
            printf("%-40s %-10u %-10u\n", pCurrent->pszName, pCurrent->wType, pCurrent->dwTtl);
        }
        pCurrent = pCurrent->pNext;
    }

    // Free the memory allocated by DnsGetCacheDataTable
    LocalFree(pEntry);

    if (csv_mode) fclose(out);

    return 0;
}


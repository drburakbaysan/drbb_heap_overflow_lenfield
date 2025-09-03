/*
 * =====================================================================
 *  AUTHOR INFORMATION:
 *  Dr. Burak BAYSAN
 *  https://burak.baysan.tr
 *  Email: burak@baysan.tr
 *  Phone: +90-501-174-4899
 * =====================================================================
 *
 *  EDUCATIONAL & RESEARCH PURPOSES ONLY
 *  This program implementation a buffer overflow vulnerability
 *  in a LAB environment.
 *
 *  VULNERABILITY TYPE:
 *    - Buffer Overflow / Input Validation Weakness
 *
 *  COMPILATION:
 *    gcc -Wall -Wextra -O2 drbb_heap_overflow_lenfield.c -o drbb_heap_overflow_lenfield
 *
 *  EXECUTION (LAB ONLY):
 *    export LAB_ENV=1
 *    ./drbb_heap_overflow_lenfield "LEN:8;DATA:HELLO"
 *
 *  DEMONSTRATION (overflow):
 *    ./drbb_heap_overflow_lenfield "LEN:16;DATA:AAAAAAAAAAAAAAAAAAAA"
 *    (Overflow will occur since no length restriction is applied.)
 *
 * =====================================================================
 */

#include <stdio.h>      // printf, fprintf
#include <stdlib.h>     // malloc, calloc, free, getenv
#include <string.h>     // strlen, strstr, memcpy, strcmp
#include <stdint.h>     // integer type definitions

/*
 * Function: parse_record_insecure
 * -------------------------------
 *  Parses input of format: LEN:<number>;DATA:<string>
 *
 *  Parameters:
 *    in       - raw input string from command line
 *    out_buf  - pointer to allocated buffer (output)
 *    out_len  - parsed length value (output)
 *
 *  Returns:
 *    0   = success
 *    <0  = error code
 *
 *  NOTE: This function is intentionally insecure.
 *        - No upper bound check for LEN.
 *        - memcpy() can overflow if LEN < strlen(DATA).
 */
int parse_record_insecure(const char *in, char **out_buf, size_t *out_len) {
    if (!in || !out_buf || !out_len) return -1; // sanity check for NULL pointers

    // Step 1: Find "LEN:" and "DATA:" substrings
    const char *lp = strstr(in, "LEN:");   // pointer to LEN declaration
    const char *dp = strstr(in, "DATA:");  // pointer to DATA section
    if (!lp || !dp || dp < lp) return -3;  // ensure correct order

    // Step 2: Extract integer value from LEN
    int len = -1;
    if (sscanf(lp, "LEN:%d;", &len) != 1) return -4; // failed to parse integer

    if (len < 0) return -5; // negative lengths are invalid

    // Step 3: Extract the data string after "DATA:"
    const char *data = dp + 5;         // skip "DATA:"
    size_t data_len = strlen(data);    // length of actual data provided

    // Step 4: Allocate buffer of size "len"
    // !!!! This is insecure because "len" may be larger than "data_len"
    char *buf = (char*)calloc(len + 1, 1); // allocate len+1 bytes (extra 1 for '\0')
    if (!buf) return -6;                   // allocation failure

    // Step 5: Copy data into buffer
    // !!!! No bounds check here → if data_len > len, buffer overflow occurs
    memcpy(buf, data, data_len);

    // Step 6: Null-terminate buffer
    buf[len] = '\0';

    // Step 7: Output results
    *out_buf = buf;
    *out_len = (size_t)len;
    return 0;
}

/*
 * Function: main
 * --------------
 *  Entry point of program. Applies calls parser.
 */
int main(int argc, char **argv) {
    // Require input argument
    if (argc < 2) {
        fprintf(stderr, "Usage: %s \"LEN:<n>;DATA:<string>\"\n", argv[0]);
        return 1;
    }

    // Step A: Prepare output variables
    char *parsed = NULL;        // will hold dynamically allocated buffer
    size_t parsed_len = 0;      // will hold parsed LEN value

    // Step B: Call vulnerable parser
    int ret = parse_record_insecure(argv[1], &parsed, &parsed_len);

    // Step C: Check return code
    if (ret != 0) {
        fprintf(stderr, "[ERROR] Parsing failed (code=%d)\n", ret);
        return 1;
    }

    // Step D: Print parsed output
    printf("[OUTPUT] Parsed record (%zu bytes): %s\n", parsed_len, parsed);

    // Step E: Free allocated memory
    free(parsed);

    return 0;
}

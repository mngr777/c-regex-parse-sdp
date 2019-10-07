#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>

static const char SDP[] =
    "v=0\n"
    "o=ice4j.org 0 0 IN IP4 172.17.0.36\n"
    "s=-\n"
    "t=0 0\n"
    "a=ice-options:trickle\n"
    "a=ice-ufrag:2du6i19e1neov5\n"
    "a=ice-pwd:3864tasnd8cnoq5huf4jr8oa67\n"
    "m=audio 55557 RTP/AVP 0\n"
    "c=IN 172.17.0.36 IP4\n"
    "a=mid:audio\n"
    "a=candidate:1 1 udp 2130706431 fe80::3a0a:94ff:fe5f:d848 55557 typ host\n"
    "a=candidate:2 1 udp 2130706431 172.17.0.36 55557 typ host\n"
    "a=candidate:3 1 udp 1677724415 212.98.165.50 55557 typ srflx raddr 172.17.0.36 rport 55557";

#define IP6_REGEX "[[:xdigit:]\\.:]+"

#define PRINT_MATCH(_str, _label, _match)                               \
    if (_match.rm_so == -1) {                                           \
        printf("%s: no match\n", (_label));                             \
    } else {                                                            \
        printf("%s: `%.*s'\n", (_label), (_match).rm_eo - (_match).rm_so, (_str) + (_match).rm_so); \
    }

static const char CandidateAttribute[] = "candidate";

/* RegEx for media line: label(1), port(2) */
static const char MediaRE[] = "^m=([^[:space:]]+)[[:space:]]+([[:digit:]]+)";

/* RegEx for connection line: IP address(2) */
static const char ConnectionRE[] = "^c=IN[[:space:]]+(IP[46][[:space:]]+)?(" IP6_REGEX ")";

/* RegEx for attribute line: name(1)[, value(2)] */
/* is match valid with no value (rm_so == lineLength) ?? */
static const char AttributeRE[] = "^a=([^:]+):?([^\\\r\\\n]*)";

/* RegEx for `candidate' attribute value: */
static const char CandidateValueRE[] =
    "^([[:digit:]]+)[[:space:]]+"    /* foundation(1) */
    "([[:digit:]]+)[[:space:]]+"     /* comp_id(2) */
    "([[:alpha:]]+)[[:space:]]+"     /* transport(3) */
    "([[:digit:]]+)[[:space:]]+"     /* prio(4) */
    "(" IP6_REGEX ")[[:space:]]+"    /* IP address(5) */
    "([[:digit:]]+)[[:space:]]+"     /* port(6) */
    "typ[[:space:]]+([[:alpha:]]+)"; /* type(7) */

int parse(const char *sdp);
void parse_line(const char *line);
int parse_media(const char *line);
int parse_connection(const char *line);
int parse_attribute(const char *line);
int parse_candidate_value(const char *value);

int main() {
    printf("%s\n--------------------\n", SDP);
    parse(SDP);
    return 0;
}

int parse(const char *sdp) {
    const char *p = sdp;
    const char *pn;
    char *line = NULL;
    size_t line_size = 0;
    do {
        pn = strchr(p, '\n');
        if (pn == NULL) {
            parse_line(p);
        } else {
            size_t length = pn - p;
            if (length > 0) {
                if (line == NULL || line_size < length + 1) {
                    line = (char*) realloc(line, (length + 1) * sizeof(char));
                    if (line == NULL)
                        return -1;
                    line_size = length + 1;
                }
                strncpy(line, p, length);
                line[length] = '\0';
                parse_line(line);
            }
            p = pn + 1;
        }
    } while (pn != NULL);
    if (line != NULL) free(line);

    return 0;
}

void parse_line(const char *line) {
    int rc = -3;
    switch (line[0]) {
        case 'm':
            rc = parse_media(line);
            break;
        case 'c':
            rc = parse_connection(line);
            break;
        case 'a':
            rc = parse_attribute(line);
            break;
    }
    if (rc == -1) {
        printf("Failed to compile regex\n");
    } else if (rc == -2) {
        printf("No match\n");
    } if (rc != -3) {
        printf("\n");
    }
}

int parse_media(const char *line) {
    printf("parsing media line: `%s'\n", line);
    regex_t re;
    if (regcomp(&re, MediaRE, REG_EXTENDED) != 0)
        return -1;

    int rc = 0;
    const size_t nmatch = 3;
    regmatch_t pmatch[nmatch];
    if (regexec(&re, line, nmatch, pmatch, 0) == 0) {
        PRINT_MATCH(line, "label", pmatch[1]);
        PRINT_MATCH(line, "port", pmatch[2]);
    } else {
        rc = -2;
    }

    regfree(&re);

    return rc;
}

int parse_connection(const char *line) {
    printf("parsing connection line: `%s'\n", line);
    regex_t re;
    if (regcomp(&re, ConnectionRE, REG_EXTENDED) != 0)
        return -1;

    int rc = 0;
    size_t nmatch = 3;
    regmatch_t pmatch[nmatch];
    if (regexec(&re, line, nmatch, pmatch, 0) == 0) {
        PRINT_MATCH(line, "IP address", pmatch[2]);
    } else {
        rc = -2;
    }

    regfree(&re);

    return rc;
}

int parse_attribute(const char *line) {
    printf("parsing attribute line: `%s'\n", line);
    regex_t re;
    if (regcomp(&re, AttributeRE, REG_EXTENDED) != 0)
        return -1;

    int rc = 0;
    size_t nmatch = 3;
    regmatch_t pmatch[nmatch];
    if (regexec(&re, line, nmatch, pmatch, 0) == 0) {
        PRINT_MATCH(line, "name", pmatch[1]);
        PRINT_MATCH(line, "value", pmatch[2]);

        if (strncmp(line + pmatch[1].rm_so, CandidateAttribute, pmatch[1].rm_eo - pmatch[1].rm_so) == 0) {
            parse_candidate_value(line + pmatch[2].rm_so);
        }
    } else {
        rc = -2;
    }

    regfree(&re);

    return rc;
}

int parse_candidate_value(const char *value) {
    printf("parsing candidate value:\n");

    regex_t re;
    if (regcomp(&re, CandidateValueRE, REG_EXTENDED) != 0)
        return -1;

    int rc = 0;
    size_t nmatch = 8;
    regmatch_t pmatch[nmatch];
    if (regexec(&re, value, nmatch, pmatch, 0) == 0) {
        PRINT_MATCH(value, "foundation", pmatch[1]);
        PRINT_MATCH(value, "comp_id", pmatch[2]);
        PRINT_MATCH(value, "transport", pmatch[3]);
        PRINT_MATCH(value, "prio", pmatch[4]);
        PRINT_MATCH(value, "IP address", pmatch[5]);
        PRINT_MATCH(value, "port", pmatch[6]);
        PRINT_MATCH(value, "type", pmatch[7]);
    } else {
        rc = -2;
    }

    regfree(&re);

    return rc;
}

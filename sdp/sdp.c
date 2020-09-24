#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include "sdp.h"
#if defined _MSC_VER && _MSC_VER < 1600
#define snprintf _snprintf
#define strtoll  _strtoui64
#else
#define _snscanf(str, len, fmt, ...) sscanf(str, fmt, __VA_ARGS__)
#endif
#define PSTR_FVA(ps)  (ps).len,(ps).ptr
#define PSTR_FMT      "%-.*s"
#define PSTR_LEN(ps)  (ps).len
#define PSTR_CMP(ps1,ps2)  ((ps1.len!=ps2.len) ? ps1.len-ps2.len:strncmp(ps1.ptr,ps2.ptr,ps1.len))

static const char*
load_next_entry(const char *p, const char **key, sdpstr *val, int* line)
{
    const char* endl;
    if (!p[0]) {
failed:
        *key = val->ptr = p;
        val->len = 0;
        return p;
    }
    else if (p[1] != '=') {
        endl = p;
        for (p += 2; *p && *p != '='; ++p);
        if (!p[0]) goto failed;
        val->ptr = p; /* restore point */
        for (--p; p > endl && isspace(*p); --p);
        *key = p;
        p = val->ptr;
    }
    else {
        *key = p++;
    }
    assert(*p == '=');
    if (!(endl = strstr(++p, "\r\n")))
        for (endl = p; *endl && *endl != '\n'; ++endl);

    /* strip value */
    while (*p && p < endl && isspace(*p)) ++p;
    val->ptr = p;
    for (p = endl-1; p > val->ptr && isspace(*p); --p);
    val->len = (p < val->ptr ? 0 : p - val->ptr + 1);

    while (*endl && isspace(*endl)) {
        if (*endl == '\n') line[0]++;
        ++endl;
    }

    return endl;
}

static void
split_values(sdpstr *val, const char sep, const char *fmt, ...)
{
    va_list va;
    const char* p = val->ptr, *end = p+val->len;

    va_start(va, fmt);
    while (*p == sep && p < end) p++;
    while (*fmt && p < end) {
        sdpstr* ps; int *i; long long int *l; second_t *t;

        switch (*fmt++) {
        case 's':
            ps = va_arg(va, sdpstr*);
            ps->ptr = p;
            while (p < end && *p != sep) p++;
            ps->len = p - ps->ptr;
            break;
        case 'l':
            l = va_arg(va, long long*);
            *l = strtoll(p, (char**)&p, 10);
            break;
        case 'i':
            i = va_arg(va, int *);
            *i = strtol(p, (char**)&p, 10);
            break;
        case 't':
            t = va_arg(va, second_t *);
            *t = strtol(p, (char**)&p, 10);
            switch (*p) {
            case 'd': *t *= 86400; p++; break;
            case 'h': *t *=  3600; p++; break;
            case 'm': *t *=    60; p++; break;
            }
            break;
        default:
            if (*p != fmt[-1]) goto clean;
            ++p;
        }
        while (*p == sep && p < end) p++;
    }
clean:
    va_end(va);
    val->len -= p - val->ptr;
    val->ptr = p;
}

#define GET_CONN_INFO(conn) do {                                    \
    if (key[0] == 'c') {                                            \
        split_values(&value, ' ', "sss",                            \
            &conn.nettype, &conn.addrtype, &conn.address);          \
        if (PSTR_LEN(value)) RET_ERR(CONNECTION);                   \
        p = load_next_entry(p, &key, &value, &line);                \
    }                                                               \
} while (0)

#define GET_BANDWIDTH_INFO(bw) do {                                 \
    while (key[0] == 'b') {                                         \
        if (bw ## _count >=  MAX_SDP_BW) RET_ERR(BW);               \
        split_values(&value, ':', "ss", &bw[bw ## _count].bwtype,   \
            &bw[bw ## _count].bandwidth);                           \
        if (PSTR_LEN(value)) RET_ERR(BW);                           \
        bw ## _count++;                                             \
        p = load_next_entry(p, &key, &value, &line);                \
    }                                                               \
} while (0)

#define LOAD_FACULTATIVE_STR(k, field) do {                         \
    if (key[0] == k) {                                              \
        field = value;                                              \
        p = load_next_entry(p, &key, &value, &line);                \
    }                                                               \
} while (0)

#define LOAD_MULTIPLE_FACULTATIVE_STR(k, field, type) do {          \
    while (key[0] == k) {                                           \
        if (field ## _count >=  MAX_SDP_ ## type) RET_ERR(type);    \
        field[field ## _count ++] = value;                          \
        p = load_next_entry(p, &key, &value, &line);                \
    }                                                               \
} while (0)

#define BEGIN_RANGE_FACULTATIVE(k, field, cur, type) do {           \
    field ## _start = cur ## _count;                                \
    while (key[0] == k) {                                           \
        if (field ## _start + field ## _count >=  MAX_SDP_ ## type) \
            RET_ERR(type);                                          \

#define END_RANGE_FACULTATIVE(field, cur)                           \
        p = load_next_entry(p, &key, &value, &line);                \
    }                                                               \
    cur ## _count += field ## _count;                               \
} while (0)


#define LOAD_RANGE_FACULTATIVE_STR(k, field, cur, type)             \
    BEGIN_RANGE_FACULTATIVE(k, field, cur, type)                    \
    sdp->cur[field ## _start + field ## _count ++] = value;         \
    END_RANGE_FACULTATIVE(field, cur)

#define GET_RANGE_BANDWIDTH(field)                                  \
    BEGIN_RANGE_FACULTATIVE('b', field, bw, BW)                     \
    split_values(&value, ':', "ss",                                 \
        &sdp->bw[field ## _start + field ## _count].bwtype,         \
        &sdp->bw[field ## _start + field ## _count].bandwidth);     \
    if (PSTR_LEN(value)) RET_ERR(BW);                               \
    field ## _count ++;                                             \
    END_RANGE_FACULTATIVE(field, bw)

#define GET_RANGE_ATTRIBUTE(field)                                  \
    LOAD_RANGE_FACULTATIVE_STR('a', field, attribute, ATTRIBUTE) 

#define RET_ERR(err) do {                                           \
    ret = ERR_SDP_## err;                                           \
    fprintf(stderr, "** Failed SDP_"#err" at line %d: %-.*s\n",     \
        line, (int)(p-key), key);                                   \
    goto clean;\
} while (0)

int sdp_parse(struct sdp_t* sdp, const char *p, char** errptr)
{
    int ret = 0, line = 0;
    const char *key;
    sdpstr value;
    count_t attribute_count, bw_count, repeat_count;

    memset(sdp, 0, sizeof(*sdp));

    /* Protocol version (mandatory, only 0 supported) */
    p = load_next_entry(p, &key, &value, &line);
    if (key[0] == 'v') {
        if (value.len != 1 || !p) RET_ERR(VERSION);
        sdp->proto_version = value.ptr[0] - '0';
        if (sdp->proto_version != 0) RET_ERR(VERSION);
    }

    /* Origin field (mandatory) */
    p = load_next_entry(p, &key, &value, &line);
    if (key[0] == 'o') {
        if (!p) RET_ERR(ORIGIN);
        struct sdp_origin *o = &sdp->origin;
        split_values(&value, ' ', "sllsss", &o->username, &o->sess_id,
            &o->sess_version, &o->nettype, &o->addrtype, &o->addr);
        if (PSTR_LEN(value)) RET_ERR(ORIGIN);
    }

    /* Session name field (mandatory) */
    p = load_next_entry(p, &key, &value, &line);
    if (key[0] == 's') {
        if (!p) RET_ERR(SESSION);
        sdp->session_name = value;
    }
    p = load_next_entry(p, &key, &value, &line);

    /* Information field */
    LOAD_FACULTATIVE_STR('i', sdp->information);

    /* URI field */
    LOAD_FACULTATIVE_STR('u', sdp->uri);

    /* Email addresses */
    LOAD_MULTIPLE_FACULTATIVE_STR('e', sdp->email, EMAIL);

    /* Phone numbers */
    LOAD_MULTIPLE_FACULTATIVE_STR('p', sdp->phone, PHONE);

    /* Connection information */
    GET_CONN_INFO(sdp->connection);

    /* Bandwidth fields */
    GET_BANDWIDTH_INFO(sdp->bw);

    /* Time fields (at least one mandatory) */
    repeat_count = 0;
    while (key[0] == 't') {
        struct sdp_time *tf;
        if (sdp->time_count >= MAX_SDP_TIME) RET_ERR(TIME);
        tf = &sdp->time[sdp->time_count++];

        split_values(&value, ' ', "ll", &tf->start_time, &tf->stop_time);
        if (PSTR_LEN(value)) RET_ERR(TIME);
        p = load_next_entry(p, &key, &value, &line);

        tf->repeat_start = repeat_count;
        while (key[0] == 'r') {
            struct sdp_repeat *rf;
            if (tf->repeat_start + tf->repeat_count >= MAX_SDP_REPEAT) RET_ERR(REPEAT);
            rf = &sdp->repeat[tf->repeat_start + tf->repeat_count++];

            split_values(&value, ' ', "tt", &rf->interval, &rf->duration);
            while (PSTR_LEN(value)) {
                if (rf->offset_count >= MAX_SDP_REPEA_OFFSET) RET_ERR(REPEA_OFFSET);
                split_values(&value, ' ', "t", &rf->offset[rf->offset_count++]);
            }
            p = load_next_entry(p, &key, &value, &line);
        }
        repeat_count += tf->repeat_count;
    }

    /* Zone adjustments */
    if (key[0] == 'z') {
        while (PSTR_LEN(value)) {
            struct sdp_zone_adjustment *za;
            if (sdp->zone_adjustment_count >= MAX_SDP_ZONE_ADJUSTMENT) RET_ERR(ZONE_ADJUSTMENT);

            za = &sdp->zone_adjustment[sdp->zone_adjustment_count++];
            split_values(&value, ' ', "tt", &za->adjust, &za->offset);
        }
        p = load_next_entry(p, &key, &value, &line);
    }

    /* Encryption key */
    LOAD_FACULTATIVE_STR('k', sdp->encrypt_key);

    /* Media attributes */
    LOAD_MULTIPLE_FACULTATIVE_STR('a', sdp->attribute, ATTRIBUTE);

    /* Media descriptions */
    attribute_count = sdp->attribute_count;
    bw_count = sdp->bw_count;
    while (key[0] == 'm') {
        struct sdp_media *md;
        if (sdp->media_count >= MAX_SDP_MEDIA) RET_ERR(MEDIA);
        md = &sdp->media[sdp->media_count++];

        split_values(&value, ' ', "si/i", &md->info.type, &md->info.port, &md->info.port_n);
        if (PSTR_LEN(md->info.type) == 0 || md->info.port == 0) RET_ERR(MEDIA);

        split_values(&value, ' ', "s", &md->info.proto);
        if (PSTR_LEN(md->info.proto) == 0) RET_ERR(MEDIA_PROTO);

        md->info.fmt = value;
        if (strstr(md->info.proto.ptr, "RTP")) {
            while (PSTR_LEN(value)) {
                int pltype;
                if (md->info.pltype_count >= MAX_SDP_MEDIA_PLTYPE) RET_ERR(MEDIA_PLTYPE);
                split_values(&value, ' ', "i", &pltype);
                md->info.pltype[md->info.pltype_count++] = pltype;
            }
        }
        p = load_next_entry(p, &key, &value, &line);

        LOAD_FACULTATIVE_STR('i', md->title);
        GET_CONN_INFO(md->connection);
        GET_RANGE_BANDWIDTH(md->bw);
        LOAD_FACULTATIVE_STR('k', md->encrypt_key);
        GET_RANGE_ATTRIBUTE(md->attribute);
    }
clean:
    if (errptr) *errptr = (char*)value.ptr;
    return ret;
}

int find_pstr(const char *key, const sdpstr attr[], int nattr)
{
    int i, klen = (int)strlen(key);

    for (i = 0; i < nattr; i++) {
        if (attr[i].len >= klen && !strncmp(attr[i].ptr, key, klen))
            return i;
    }
    return -1;
}

int sdp_dump(char* payload, int s, const struct sdp_t *sdp)
{
    int n;
    size_t i, j, k;
    char* p = payload;

#define printf(fmt, ...) do{\
    if ((n=snprintf(p, s, fmt, ##__VA_ARGS__)) < 0) return n; \
    else if (n > s) return p - payload + n; \
    else p += n, s -= n;\
} while(0)

    printf("v=%d\n", sdp->proto_version);
    printf("o="PSTR_FMT" %lld %lld "PSTR_FMT" "PSTR_FMT" "PSTR_FMT"\n", 
        PSTR_FVA(sdp->origin.username), sdp->origin.sess_id, sdp->origin.sess_version,
        PSTR_FVA(sdp->origin.nettype), PSTR_FVA(sdp->origin.addrtype), PSTR_FVA(sdp->origin.addr));
    printf("s="PSTR_FMT"\n", PSTR_FVA(sdp->session_name));

    if (PSTR_LEN(sdp->information))
        printf("i="PSTR_FMT"\n", PSTR_FVA(sdp->information));
    if (PSTR_LEN(sdp->uri))
        printf("u="PSTR_FMT"\n", PSTR_FVA(sdp->uri));

    for (i = 0; i < sdp->email_count; i++)
        printf("e="PSTR_FMT"\n", PSTR_FVA(sdp->email[i]));
    for (i = 0; i < sdp->phone_count; i++)
        printf("p="PSTR_FMT"\n", PSTR_FVA(sdp->phone[i]));

    if (PSTR_LEN(sdp->connection.nettype)
        && PSTR_LEN(sdp->connection.addrtype) && PSTR_LEN(sdp->connection.address)) {
        printf("c="PSTR_FMT" "PSTR_FMT" " PSTR_FMT"\n",
            PSTR_FVA(sdp->connection.nettype), PSTR_FVA(sdp->connection.addrtype),
            PSTR_FVA(sdp->connection.address));
    }

    for (i = 0; i < sdp->bw_count; i++)
        printf("b="PSTR_FMT":"PSTR_FMT"\n",
            PSTR_FVA(sdp->bw[i].bwtype), PSTR_FVA(sdp->bw[i].bandwidth));

    for (i = 0; i < sdp->time_count; i++) {
        const struct sdp_time *t = &sdp->time[i];
        printf("t=%lld %lld\n", t->start_time, t->stop_time);
        for (j = 0; j < t->repeat_count; j++) {
            const struct sdp_repeat *r = &sdp->repeat[t->repeat_start+j];
            printf("r=%ld %ld", r->interval, r->duration);
            for (k = 0; k < r->offset_count; k++)
                printf(" %ld", r->offset[k]);
            printf("\n");
        }
    }

    if (sdp->zone_adjustment_count) {
        printf("z=");
        for (i = 0; i < sdp->zone_adjustment_count; i++) {
            printf("%ld %ld%s",
                sdp->zone_adjustment[i].adjust, sdp->zone_adjustment[i].offset,
                i + 1 < sdp->zone_adjustment_count ? " " : "");
        }
        printf("\n");
    }

    if (PSTR_LEN(sdp->encrypt_key))
        printf("k="PSTR_FMT"\n", PSTR_FVA(sdp->encrypt_key));

    for (i = 0; i < sdp->attribute_count; i++)
        printf("a="PSTR_FMT"\n", PSTR_FVA(sdp->attribute[i]));

    for (i = 0; i < sdp->media_count; i++) {
        const struct sdp_media *m   = &sdp->media[i];
        const struct sdp_info *info = &m->info;

        printf("m="PSTR_FMT" %d", PSTR_FVA(info->type), info->port);
        if (info->port_n) printf("/%d", info->port_n);
        printf(" "PSTR_FMT, PSTR_FVA(info->proto));

        if (info->pltype_count > 0) {
            for (j = 0; j < info->pltype_count; j++)
                printf(" %d", info->pltype[j]);
            printf("\n");
        }
        else
            printf(" "PSTR_FMT"\n", PSTR_FVA(info->fmt));

        if (PSTR_LEN(m->title))
            printf("i="PSTR_FMT"\n", PSTR_FVA(m->title));
        if (PSTR_LEN(m->connection.nettype)
            && PSTR_LEN(m->connection.addrtype) && PSTR_LEN(m->connection.address)) {
            printf("c="PSTR_FMT" "PSTR_FMT" "PSTR_FMT"\n",
                PSTR_FVA(m->connection.nettype), PSTR_FVA(m->connection.addrtype),
                PSTR_FVA(m->connection.address));
        }
        for (j = 0; j < m->bw_count; j++)
            printf("b="PSTR_FMT":"PSTR_FMT"\n",
                PSTR_FVA(sdp->bw[m->bw_start+j].bwtype), PSTR_FVA(sdp->bw[m->bw_start+j].bandwidth));
        if (PSTR_LEN(m->encrypt_key))
            printf("k="PSTR_FMT"\n", PSTR_FVA(m->encrypt_key));
        for (j = 0; j < m->attribute_count; j++)
            printf("a="PSTR_FMT"\n", PSTR_FVA(sdp->attribute[m->attribute_start+j]));
    }
#undef printf
    return p - payload;
}
union attr_t {
    sdpstr pstr;
    struct {
        char plname[32];
        int pltype;
        int plfreq;
        int channels;
    };
};
static void
pstr_parse(union attr_t * attr, const sdpstr *a) { attr->pstr = *a; }
//static int
//pstr_cmp(const union attr_t* a1, const sdpstr* a2) { return PSTR_CMP(a1->pstr, a2[0]); }
static int
part_cmp(const union attr_t* a1, const sdpstr* a) /* compare after ' '*/
{
    int i,j,n;
    for (i=0; i<a1->pstr.len && a1->pstr.ptr[i] != ' ';++i);
    for (j=0; j<a->len && a->ptr[j] != ' ';++j);
    n = a1->pstr.len - i;
    if (n != a->len - j) return n -  (a->len - j);
    return strncmp(a1->pstr.ptr+i, a->ptr+j, n);
}

static void 
answer_attr(const char* prefix,
    struct sdp_media *m1, sdpstr *a1,
    const struct sdp_media *m2, const sdpstr *a2,
    void (*parse)(union attr_t*, const sdpstr*),
    int (*compare)(const union attr_t*,const sdpstr*))
{
    union attr_t v1;
    int n1 = 0, k1 = find_pstr(prefix, a1, m1->attribute_count), n2, k2;
    while (k1 >= 0) {
        n1 += k1;
        parse(&v1, a1+n1);

        n2 = 0;
        k2 = find_pstr(prefix, a2, m2->attribute_count);
        while (k2 >= 0) {
            n2 += k2;

            if(compare(&v1, a2+n2) == 0) break;
            ++n2;
            k2 = find_pstr(prefix, a2+n2, m2->attribute_count-n2);
        }
        if (k2 < 0) { /* delete attribute */
            m1->attribute_count-- ;
            if (n1 < m1->attribute_count)
                memcpy(a1+n1, a1+m1->attribute_count, sizeof(sdpstr));
        }
        else {
            ++n1;
        }
        k1 = find_pstr(prefix, a1+n1, m1->attribute_count-n1);
    }
}
static void
rtpmap_parse(union attr_t * attr, const sdpstr *a)
{
    _snscanf(a->ptr, a->len, "rtpmap:%d %[^/]/%d/%d",
        &attr->pltype, attr->plname, &attr->plfreq, &attr->channels);
}
static int
rtpmap_cmp(const union attr_t* a1, const sdpstr* a)
{
    union attr_t a2;
    _snscanf(a->ptr, a->len, "rtpmap:%d %[^/]/%d/%d",
        &a2.pltype, a2.plname, &a2.plfreq, &a2.channels);
    return strcmp(a1->plname, a2.plname);
}
int sdp_answer(struct sdp_t *sdp1, const struct sdp_t *sdp2)
{
    int i=0;
    while (i < sdp1->media_count) {
        struct sdp_media *m1 = sdp1->media+i;
        /* find the same media info type */
        int j=0;
        while (j<sdp2->media_count) {
            if (PSTR_CMP(m1->info.type, sdp2->media[j].info.type) == 0)
                break;
            ++j;
        }
        if (j == sdp2->media_count) {/* delete media */
            sdp1->media_count--;
            if (i < sdp1->media_count)
                memcpy(m1, sdp1->media + sdp1->media_count, sizeof(struct sdp_media));
            continue;
        }
        ++i;

        /* negotiate attribute */
        sdpstr* a1 = sdp1->attribute + m1->attribute_start;
        const struct sdp_media* m2 = sdp2->media+j;
        const sdpstr *a2 = sdp2->attribute + m2->attribute_start;

        answer_attr("rtpmap:", m1, a1, m2, a2, rtpmap_parse, rtpmap_cmp);
        answer_attr("extmap:", m1, a1, m2, a2, pstr_parse, part_cmp);
        answer_attr("rtcp-fb:", m1, a1, m2, a2, pstr_parse, part_cmp);
    }
    return 0;
}

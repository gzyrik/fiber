#ifndef SDP_H
#define SDP_H
#ifdef __cplusplus
extern "C" {
#endif
/* seconds */
typedef unsigned long second_t;
/* NTP time, seconds since 1900 */
typedef unsigned long long ntptime_t;
typedef unsigned char count_t;

enum {
    /* capacity of SDP field */
    MAX_SDP_ATTRIBUTE = 128, /*< max rows of 'a=' */
    MAX_SDP_MEDIA = 8, /*< max rows of 'm=' */
    MAX_SDP_MEDIA_PLTYPE = 16, /*< max number payload type in 'm=' */
    MAX_SDP_BW = 8,    /*< max rows of 'b=' */
    MAX_SDP_EMAIL = 2, /*< max rows of 'e=' */
    MAX_SDP_PHONE = 2, /*< max rows of 'p=' */
    MAX_SDP_TIME = 4,  /*< max rows of 't=' */
    MAX_SDP_REPEAT = 4,/* max row of 'r=' */
    MAX_SDP_REPEA_OFFSET = 6, /*< max offset fmt in 'r=' */
    MAX_SDP_ZONE_ADJUSTMENT = 4, /*< max pair adjust-offset in 'z=' */

    /* error of sdp_parse() */
    ERR_SDP_VERSION = 1,
    ERR_SDP_CONNECTION,
    ERR_SDP_ORIGIN,
    ERR_SDP_SESSION,
    ERR_SDP_BW,
    ERR_SDP_EMAIL,
    ERR_SDP_PHONE,
    ERR_SDP_ATTRIBUTE,
    ERR_SDP_MEDIA_PLTYPE,
    ERR_SDP_TIME,
    ERR_SDP_REPEAT,
    ERR_SDP_REPEA_OFFSET,
    ERR_SDP_ZONE_ADJUSTMENT,
    ERR_SDP_MEDIA,
    ERR_SDP_MEDIA_PROTO,
};

typedef struct { const char *ptr; int len; } PSTR;

struct sdp_connection {
    PSTR nettype;
    PSTR addrtype;
    PSTR address;
};

struct sdp_bandwidth {
    PSTR bwtype;
    PSTR bandwidth;
};

struct sdp_time {
    ntptime_t start_time; 
    ntptime_t stop_time;
    /* start index of sdp_t.repeat[] */
    count_t repeat_start;
    count_t repeat_count;
};

struct sdp_media {
    struct sdp_info {
        PSTR type;
        int port;
        int port_n; /*< number of ports */
        PSTR proto;
        PSTR fmt;
        count_t pltype_count;
        char pltype[MAX_SDP_MEDIA_PLTYPE];
    } info;
    PSTR title;
    struct sdp_connection connection;

    /* start index of sdp_t.bw[] */
    count_t bw_start;
    count_t bw_count;

    PSTR encrypt_key;

    /* start index of sdp_t.attribute[] */
    count_t attribute_start;
    count_t attribute_count;
};

struct sdp_t {
    /* protocol version MUST 0 */
    unsigned char proto_version;

    struct sdp_origin {
        /* MUST NOT contain spaces, instead "-" */
        PSTR username; 
        ntptime_t sess_id;
        ntptime_t sess_version;
        PSTR nettype;
        PSTR addrtype;
        PSTR addr;
    } origin;

    PSTR session_name;
    PSTR information;
    PSTR uri;

    count_t email_count;
    PSTR email[MAX_SDP_EMAIL]; 

    count_t phone_count;
    PSTR phone[MAX_SDP_PHONE]; 

    struct sdp_connection connection;

    count_t bw_count;
    struct sdp_bandwidth bw[MAX_SDP_BW];

    struct sdp_repeat {
        second_t interval;
        second_t duration;
        count_t offset_count;
        second_t offset[MAX_SDP_REPEA_OFFSET];
    } repeat[MAX_SDP_REPEAT];

    count_t time_count;
    struct sdp_time time[MAX_SDP_TIME];

    count_t zone_adjustment_count;
    struct sdp_zone_adjustment {
        second_t adjust;
        second_t offset;
    } zone_adjustment[MAX_SDP_ZONE_ADJUSTMENT];

    PSTR encrypt_key;

    count_t attribute_count;
    PSTR attribute[MAX_SDP_ATTRIBUTE];

    count_t media_count;
    struct sdp_media media[MAX_SDP_MEDIA];
};

/** fill sdp_t by parse payload 
 * @return 0 for success, or ERR_SDP_* for failure
 *         and *errptr is the error position
 */
int sdp_parse(struct sdp_t* sdp, const char *payload, char** errptr);


/** remove item of answer if not exist in offer
 * compare supported
 * - mediatype
 * - rtpmap  compare plname   
 * - extmap  compare <URI> <extensionattributes>
 * - rtcp-fb
 */
int sdp_answer(struct sdp_t *answer, const struct sdp_t *offer);

/** fill payload by dump sdp_t
 * @return as 'snprintf', written length for success
 */
int sdp_dump(char* payload, int size, const struct sdp_t *sdp);

/** find value by sequential search
 * @return -1 for failure, or value index for success
 */
int find_pstr(const char *key, const PSTR attr[], int nattr);

#ifdef __cplusplus
}
#endif
#endif

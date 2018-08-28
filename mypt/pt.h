struct pt {
    void * lc;
};

#define PT_WAITING 0
#define PT_YIELDED 1
#define PT_EXITED  2
#define PT_ENDED   3

#define LC_CONCAT2(s1, s2) s1##s2
#define LC_CONCAT(s1, s2) LC_CONCAT2(s1, s2)
#define LC_SET(s) do { \
    LC_CONCAT(LC_LABEL, __LINE__): \
    (s) = &&LC_CONCAT(LC_LABEL, __LINE__); \
} while (0)

#define PT_BEGIN(pt) {\
    char PT_YIELD_FLAG = 1; \
    if ((pt)->lc != (void*)0) goto *((pt)->lc);

#define PT_END(pt) PT_YIELD_FLAG=0; (pt)->lc=0; return PT_ENDED; }

#define PT_YIELD(pt) do{        \
    PT_YIELD_FLAG = 0;          \
    LC_SET((pt)->lc);           \
    if (PT_YIELD_FLAG == 0) return PT_YIELDED;  \
} while(0)


#define PT_WAIT_UNTIL(pt, condition) do {\
    LC_SET((pt)->lc); \
    if(!(condition)) return PT_WAITING; \
} while(0)

#define PT_ALIVE(f) ((f) < PT_EXITED)

#define PT_WAIT_THREAD(pt, thread) PT_WAIT_UNTIL((pt), !PT_ALIVE(thread))


#define PT_YIELD_UNTIL(pt, condition) do {\
    PT_YIELD_FLAG = 0;\
    LC_SET((pt)->lc);\
    if((PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

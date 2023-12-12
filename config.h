#define HOST_MODE
// #define ROCKY
#define DEBUG 0
#define QUEUE 64
#if QUEUE
#ifdef HOST_MODE
#define ZERO_COPY 1
#endif
#endif
// #define QUEUE_2 9
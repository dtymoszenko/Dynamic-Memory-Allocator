/*
 * cache.c:
 * A cache simulator that can replay traces (from Valgrind) and output
 * statistics for the number of hits, misses, and evictions.
 * The cache utilizes the LRU replacement policy.
 *
 * Implementation and assumptions:
 *  1. Each load/store can cause at most one cache miss plus a possible eviction.
 *  2. Instruction loads (I) are ignored.
 *  3. Data modify (M) is treated as a load followed by a store to the same
 *  address. Hence, an M operation can result in two cache hits, or a miss and a
 *  hit plus a possible eviction.
 */

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

//Globals set by command line args.
int b = 0; //number of block (b) bits
int s = 0; //number of set (s) bits
int E = 0; //number of lines per set

//Globals derived from command line args.
int B; //block size in bytes: B = 2^b
int S; //number of sets: S = 2^s

//Global counters to track cache statistics in access_data().
int hit_cnt = 0;
int miss_cnt = 0;
int evict_cnt = 0;

//Global to control trace output
int verbosity = 0; //print trace if set

//Type cache_line_t: Use when dealing with cache lines.
typedef struct cache_line {
    char valid;
    mem_addr_t tag;
    //I decided to implement LRU tracking with a counter, where every cache
    //line has a counter. Every time the line is accessed the value of this counter
    //is increased by max(allcounters) + 1, and smallest counter value is then LRU
    int counter;
} cache_line_t;

//Type cache_set_t: Use when dealing with cache sets
//Note: Each set is a pointer to a heap array of one or more cache lines.
typedef cache_line_t* cache_set_t;

//Type cache_t: Use when dealing with the cache.
typedef cache_set_t* cache_t;

// Create the cache we're simulating.
cache_t cache;

/* 
 * init_cache:
 * Allocates the data structure for a cache with S sets and E lines per set.
 * Initializes all valid bits and tags with 0s.
 */
void init_cache() {
        //Actually initialize the values of B and S to 2^b and 2^s respectively
        //Piazza@779
        int calc = 1;
        for (int i = 0; i < b; i++) {
                calc = calc * 2;
        }
        B = calc;

        int calc2 = 1;
        for (int i =0; i < s; i++) {
                calc2 = calc2 * 2;
        }
        S = calc2;

        //Allocate the cache data structure for a cache w/ S sets and E lines per set
        cache = malloc(sizeof(cache_set_t) * S);

        //Check return value of malloc and exit(1) if failed to allocate memory.
        if (cache == NULL) {
             printf("unable to allocate mem\n");
             exit(1);
        }

        //The above line allocates the entire large cache, however now it is required to
        //initialize all of the individual sets that are within the cache.
        //Loop condition should be based on global variable S which contains # sets present
        for (int i = 0; i < S; i++) {
                //Allocate using malloc the sizeof a cache line multiplied by number of lines
                //that are present within a set (global variable E).
                cache[i] = malloc(sizeof(cache_line_t) * E);

                //Check if return value of creating set is null and exit(1) if memory allocation failed
                if (cache[i] == NULL) {
                        printf("unable to allocate mem\n");
                        exit(1);
                }

                //Initialize all valid bits and tags with 0s double indexing by finding set then line
                for (int j = 0; j < E; j++) {
                        cache[i][j].valid = 0;
                        cache[i][j].tag = 0;
                        cache[i][j].counter = 0;
                }
        }

}

/* 
 * free_cache:
 * Frees all heap allocated memory used by the cache.
 */
void free_cache() {
        //Iterate through entire cache and free all of the sets within it
        for (int i = 0; i < S; i++) {
                free(cache[i]);
        }
        //After freeing all of the sets within the cache, free the entire cache data structure.
        //Order matters and is important, must free the sets before simply freeing the entire cache,
        //otherwise weird memory problems will happen.
        free(cache);
}

/* 
 * access_data:
 * Simulates data access at given "addr" memory address in the cache.
 *
 * If already in cache, increment hit_cnt
 * If not in cache, cache it (set tag), increment miss_cnt
 * If a line is evicted, increment evict_cnt
 */
void access_data(mem_addr_t addr) {
        //In all cases, we need to look at s and t bits
        //We need the s bits to determine which set to look at
        //We need the t bits to to see if it matches the tag

        //In an address, the first bits are b-bits, and the second
        //part of the bits represent the s-bits, and lastly there are t-bits
        //This means I need to ignore all of the b and s bits at the beginning
        //In order to ONLY get the t bits at the end.
        //To do this, binary right shift the variable addr by s+b
        //This value will be useful to identify the tag
        mem_addr_t tagBitValue = addr >> (s+b);

        //Next, I need to get the value from the s-bits, which shows what set
        //The s-bits are in the middle between the b bits and the t bits.
        //In order to access them, use a mask and shifting (Piazza)
        //Set the location of the s-bits to be value 1 and everything else to be 0.
        mem_addr_t maskSBits = ((1 << s) -1) << b;

        //In order to get the sBit value, use the mask AND with addr and then shift to
        //the right by b bits. This makes the sbits at the beginning of the address
        //and everything else 0, meaning the value of sbits can be successfully be accessed.
        mem_addr_t setBitValue = (addr & maskSBits) >> b;

        //The way I chose to implemenet LRU was with a counter, increment the
        //counter of everything in this line by 1, which will help to determine
        //smallest counter value (aka least recently used) and that one will be chosen
        //to be evicted
        for (int i = 0; i < E; i++) {
                cache[setBitValue][i].counter = cache[setBitValue][i].counter + 1;
        }

        //There are 3 cases, incrementally develop for each case:
        //Case 1: If already in cache, increment hit_cnt

        //Iterate through all of the lines in the set.
        for (int i = 0; i < E; i++) {
                //Check if the line within the set is valid (valid==1), and the tag matches
                if ( (cache[setBitValue][i].valid == 1) && cache[setBitValue][i].tag == tagBitValue) {
                        //increment count for hits
                        hit_cnt = hit_cnt + 1;

                        //Set the value of counter to 0 to indicate this has just been used
                        //(This is for keeping track of LRU) for eviction
                        cache[setBitValue][i].counter = 0;

                        //Return from the method since there is nothing else to be done,
                        //don't have to look at case 2 or 3.
                        return;
                }
        }

        //Case 2: If not in cache, cache it (set tag), increment miss_cnt

        //Traverse through lines of cache (again..)
        for (int i = 0; i < E; i++) {
                //Check if the valid bit!=1, which means checking if cache line is not valid
                if (cache[setBitValue][i].valid != 1) {
                        //Since this is a miss, increment miss_cnt variable.
                        miss_cnt = miss_cnt + 1;

                        //Update bits and tag and LRU tracker value (counter)
                        cache[setBitValue][i].tag = tagBitValue;
                        cache[setBitValue][i].valid = 1;
                        cache[setBitValue][i].counter = 0;

                        //Return since a free space was found to cache it
                        return;
                }
        }

        //Cache 3: If a line is evicted, increment evict_cnt

        //Reaching this case means that the line was full and there was no open space in the set
        //In order to decide which line in the set to evict, use LRU by looking at the counter value
        //The HIGHEST counter value represents the least recently used, since every time I increment
        //by 1, and it is set to 0 when accessed.
        int lruCheck = -1;

        //Keep track of line index that has the highest counter value, AKA is the least recently used
        int lruIndex = -1;

        //Since this case was reached, the miss count and evict count will BOTH increase by 1
        miss_cnt = miss_cnt + 1;
        evict_cnt = evict_cnt + 1;

        //Traverse through all lines in the set and find line with the HIGHEST counter value
        for (int i = 0; i < E; i++) {
                //If current line's counter is higher than the check variable, it becomes
                //the new highest value and the check variable, check variable at end of loop
                //will get evicted
                if (cache[setBitValue][i].counter > lruCheck) {
                        lruCheck = cache[setBitValue][i].counter;
                        lruIndex = i;
                }
        }

         //Update all bits and also update counter variable to 0 (most recently used)
        cache[setBitValue][lruIndex].tag = tagBitValue;
        cache[setBitValue][lruIndex].valid = 1;
        cache[setBitValue][lruIndex].counter = 0;
}

/* 
 * replay_trace:
 * Replays the given trace file against the cache.
 *
 * Reads the input trace file line by line.
 * Extracts the type of each memory access : L/S/M
 * TRANSLATE each "L" as a load i.e. 1 memory access
 * TRANSLATE each "S" as a store i.e. 1 memory access
 * TRANSLATE each "M" as a load followed by a store i.e. 2 memory accesses
 */
void replay_trace(char* trace_fn) {
    char buf[1000];
    mem_addr_t addr = 0;
    unsigned int len = 0;
    FILE* trace_fp = fopen(trace_fn, "r");

    if (!trace_fp) {
        fprintf(stderr, "%s: %s\n", trace_fn, strerror(errno));
        exit(1);
    }

    while (fgets(buf, 1000, trace_fp) != NULL) {
        if (buf[1] == 'S' || buf[1] == 'L' || buf[1] == 'M') {
            sscanf(buf+3, "%llx,%u", &addr, &len);

            if (verbosity)
                printf("%c %llx,%u ", buf[1], addr, len);

            // GIVEN: 1. addr has the address to be accessed
            //        2. buf[1] has type of acccess(S/L/M)
            // call access_data function here depending on type of access

            //L and S are treated as load and store respectively, only 1 mem access
            if (buf[1] == 'L' || buf[1] == 'S') {
                access_data(addr);
            }
            //M is treated as load followed by store, which means 2 mem access
            else if (buf[1] == 'M') {
                access_data(addr);
                access_data(addr);
            }

            if (verbosity)
                printf("\n");
        }
    }
    fclose(trace_fp);
}

/*
 * print_usage:
 * Print information on how to use cache to standard output.
 */
void print_usage(char* argv[]) {
    printf("Usage: %s [-hv] -s <num> -E <num> -b <num> -t <file>\n", argv[0]);
    printf("Options:\n");
    printf("  -h         Print this help message.\n");
    printf("  -v         Optional verbose flag.\n");
    printf("  -s <num>   Number of s bits for set index.\n");
    printf("  -E <num>   Number of lines per set.\n");
    printf("  -b <num>   Number of b bits for block offsets.\n");
    printf("  -t <file>  Trace file.\n");
    printf("\nExamples:\n");
    printf("  linux>  %s -s 4 -E 1 -b 4 -t traces/yi.trace\n", argv[0]);
    printf("  linux>  %s -v -s 8 -E 2 -b 4 -t traces/yi.trace\n", argv[0]);
    exit(0);
}

/*
 * print_summary:
 * Prints a summary of the cache simulation statistics to a file.
 */
void print_summary(int hits, int misses, int evictions) {
    printf("hits:%d misses:%d evictions:%d\n", hits, misses, evictions);
    FILE* output_fp = fopen(".cache_results", "w");
    assert(output_fp);
    fprintf(output_fp, "%d %d %d\n", hits, misses, evictions);
    fclose(output_fp);
}

/*
 * main:
 * Main parses command line args, makes the cache, replays the memory accesses
 * free the cache and print the summary statistics.
 */
int main(int argc, char* argv[]) {
    char* trace_file = NULL;
    char c;

    // Parse the command line arguments: -h, -v, -s, -E, -b, -t
    while ((c = getopt(argc, argv, "s:E:b:t:vh")) != -1) {
        switch (c) {
            case 'b':
                b = atoi(optarg);
                break;
            case 'E':
                E = atoi(optarg);
                break;
            case 'h':
                print_usage(argv);
                exit(0);
            case 's':
                s = atoi(optarg);
                break;
            case 't':
                          trace_file = optarg;
                break;
            case 'v':
                verbosity = 1;
                break;
            default:
                print_usage(argv);
                exit(1);
        }
    }

    //Make sure that all required command line args were specified.
    if (s == 0 || E == 0 || b == 0 || trace_file == NULL) {
        printf("%s: Missing required command line argument\n", argv[0]);
        print_usage(argv);
        exit(1);
    }

    //Initialize cache.
    init_cache();

    //Replay the memory access trace.
    replay_trace(trace_file);

    //Free memory allocated for cache.
    free_cache();

    //Print the statistics to a file.
    print_summary(hit_cnt, miss_cnt, evict_cnt);
    return 0;
}

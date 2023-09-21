#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include "p3Heap.h"

/*
 * This structure serves as the header for each allocated and free block.
 * It also serves as the footer for each free block but only containing size.
 */
typedef struct blockHeader {

    int size_status;

    /*
     * Size of the block is always a multiple of 8.
     * Size is stored in all block headers and in free block footers.
     *
     * Status is stored only in headers using the two least significant bits.
     *   Bit0 => least significant bit, last bit
     *   Bit0 == 0 => free block
     *   Bit0 == 1 => allocated block
     *
     *   Bit1 => second last bit
     *   Bit1 == 0 => previous block is free
     *   Bit1 == 1 => previous block is allocated
     *
     * Start Heap:
     *  The blockHeader for the first block of the heap is after skip 4 bytes.
     *  This ensures alignment requirements can be met.
     *
     * End Mark:
     *  The end of the available memory is indicated using a size_status of 1.
     *
     * Examples:
     *
     * 1. Allocated block of size 24 bytes:
     *    Allocated Block Header:
     *      If the previous block is free      p-bit=0 size_status would be 25
     *      If the previous block is allocated p-bit=1 size_status would be 27
     *
     * 2. Free block of size 24 bytes:
     *    Free Block Header:
     *      If the previous block is free      p-bit=0 size_status would be 24
     *      If the previous block is allocated p-bit=1 size_status would be 26
     *    Free Block Footer:
     *      size_status should be 24
     */
} blockHeader;

/* Global variable
 * It must point to the first block in the heap and is set by init_heap()
 * i.e., the block at the lowest address.
 */
blockHeader *heap_start = NULL;

/* Size of heap allocation padded to round to nearest page size.
 */
int alloc_size;

/*
 * Additional global variables may be added as needed below
 */
int MIN_BLOCK_SIZE = 8;

/*
 * Function for allocating 'size' bytes of heap memory.
 * Argument size: requested size for the payload
 * Returns address of allocated block (payload) on success.
 * Returns NULL on failure.
 *
 * This function must:
 * - Check size - Return NULL if size < 1
 * - Determine block size rounding up to a multiple of 8
 *   and possibly adding padding as a result.
 *
 * - Use BEST-FIT PLACEMENT POLICY to chose a free block
 *
 * - If the BEST-FIT block that is found is exact size match
 *   - 1. Update all heap blocks as needed for any affected blocks
 *   - 2. Return the address of the allocated block payload
 *
 * - If the BEST-FIT block that is found is large enough to split
 *   - 1. SPLIT the free block into two valid heap blocks:
 *         1. an allocated block
 *         2. a free block
 *         NOTE: both blocks must meet heap block requirements
 *       - Update all heap block header(s) and footer(s)
 *              as needed for any affected blocks.
  *   - 2. Return the address of the allocated block payload
 *
 *   Return if NULL unable to find and allocate block for required size
 *
 * Note: payload address that is returned is NOT the address of the
 *       block header.  It is the address of the start of the
 *       available memory for the requesterr.
 *
 */
void* balloc(int size) {
    //Trivial, if we are allocating a size of 0, we are doing nothing so just return NULL.
    if (size < 1) {
        return NULL;
    }

    //After given the size in parameter, we have to add the size for the header
    size = size + sizeof(blockHeader);

    //After adding the size of blockheader to the size, check if it is a multiple of 8.
    //If it is a multiple of 8, then no padding needs to be added, otherwise, padding has to
    //be added to make it the nearest possible multiple of 8.
    if ( (size % 8) != 0) {
        //This will always make size a multiple of 8 if it is not already
        size = size + 8 - (size % 8);
    }

    //Create the block header for the best fit-placement of the size given in parameter
    blockHeader* bestFit = NULL;
    int blockSize;
    //Define find to be the variable where we are trying to place the header at and finding best fit.
    //Initially, find is initialized to the start of the heap to ensure everything in the heap is
    //traversed, guaranteeing that the proper best fit is ALWAYS found
    blockHeader* find = NULL;
    find = heap_start;

    //Iterate through all possible available memory and try to allocate for the bestFit
    //Do this in a while loop, while we have not reached the end mark.
    //As stated in the write-up, the end mark is defined by size_status=1.
    while(find->size_status != 1) {
        //bit0 determines if the block is free or allocated, and bit1 determines if the previous block is free
        //or allocated
        //Use the information from bit0 and bit1 in the headers to traverse through the heap memory available,
        //and generally check if the size can fit based on the size_status given.
        //First, check to see if it fits by comparing size and size status variables.
        //int bob = find->size_status;
        //printf("%d", bob);
        //int check = find->size_status & ~3;
        //printf("%d", check);
        if ( (find->size_status & ~3) >= size) {
                //Then, use information from bit0 about free/allocated
                //to determine if it is possible to put it in the memory there
                //PERSONAL NOTE WHEN LOOKING BACK:
                // & 1 gets least significant bit in C.
                //DEBUG FIX: fix parenthesis due to precdence order in C with & and ==
                if ( (find->size_status & 1) == 0) {
                        //If bestFit is NULL, that means nothing has been found yet, allocate it here
                        //Also, if bestFit has been found, we compare to see if the current one is better
                        //than the best fit we have found so far. If it is, set it to bestFit
                        if (bestFit == NULL || (bestFit->size_status & ~3) > (find->size_status & ~3) ) {
                                bestFit = find;
                                //break out of whileLoop if the bestFit is EXACT match.
                                if ( (bestFit->size_status & ~3) == size) {
                                        break;
                                }
                        }
                }
        }

         //Have to go to the next Header
        //Must extract size from size_status and then advance that many bytes to find next
        //block header in memory
        //Status is only stored in last 2 bits so get rid of last 2 bits and that is size we need to increment by
        //To ignore the last 2 bits and set them to 0, use AND with the complement of 3 (~3).
        blockSize = find->size_status & ~3;

        //Compute the next block using address of find and value of blockSize
        //BUG FIX: Using the TIP in the header of this method: find is blockHeader, which has a scale
        //factor that is NOT 1. This meant that adding blockSize to it was incorrectly scaling by the
        //size of blockHeader (I think, more debugging to find out!). To fix, cast as char* which only
        //has a scale factor of 1 and then do the addition normally... should(?) work!
        void* next = (char*)find + blockSize;

        //After scaling using char* as a factor of 1, then we can convert to a blockHeader pointer with
        //the correct address
        find = (blockHeader*) next;

    }

     //After iterating through all of the possible available memory, if we fail to find a place in memory
    //to place this, and fail to find ANY bestFit, then per the specification we simply return null and
    //end balloc() execution here
    if (bestFit == NULL) {
        return NULL;
    }

    //Case of bestFit being EXACT match in size
    if ( (bestFit->size_status & ~3) == size) {
        //Set bit0 which is the allocation bit to 1, meaning we have now allocated this
        bestFit->size_status = bestFit->size_status | 1;
        //We have to also set the previous bit to 1 for the NEXT block, meaning that
        //this block has been allocated. IMPORTANT: Make sure we are not updating the
        //end mark by checking with an if statement

        //These 3 lines are same as slightly above, finding address of NEXT Header
        blockSize = bestFit->size_status & ~3;
        void *nextHead = (char*) bestFit + blockSize;
        blockHeader* nextBlock = (blockHeader*) nextHead;

        //CHECK IF the nextBlock has size_status=1, meaning check if it is the end. IF it is, DO NOT change pbit or it will create infinite loop
        //Otherwise, set the pbit which is bit1 to 1
        if (nextBlock->size_status != 1) {
                nextBlock->size_status = nextBlock->size_status | 2;
        }

        //Calculate the address of the payload by adding the address of bestFit to the size of a blockHeader, then return.        //cast as char* for scale factor
        void* toReturn = ((char*) bestFit) + sizeof(blockHeader);
        return toReturn;
    }
    //The only other case is that it IS NOT an exact match in size, meaning we MAY need to use splitting.
    else{
        //Check if it is splittable
        if ( (bestFit->size_status & ~3) >= size+MIN_BLOCK_SIZE) {

        //If it is splittable, change the size of the block to simply fit the size
        //Then make sure to change the pbit and abit to be what they were.
        int oldPBit = -1;
        if ( (bestFit->size_status & 2) == 2) {
                oldPBit = 1;
        }
        else {
                oldPBit = 0;
        }

        //Change size to only be exact size and keep track of old size
        int oldSize = bestFit->size_status & ~3;
        bestFit->size_status = size;

        //Change pbit to 0 like it was before.
        if (oldPBit == 0) {
                bestFit->size_status = bestFit->size_status & ~2;
        }
        //change pbit to 1
        else {
                bestFit->size_status = bestFit->size_status | 2;
        }

        //Change bit0 (alloc bit) to 1 meaning this is allocated
        bestFit->size_status = bestFit->size_status | 1;

        //Create newBlock pointer to a blockHeader which will be free and split apart.
        //The remaining leftover should always be a multiple of 8
        //YOU WERE WORKING ON BLOCKSIZE FIX. JUMPING TOO MUCH CAUSING INFINITE LOOP
        //blockSize = bestFit->size_status & ~3
        blockSize = size;
        void* nextHeader = (char*)bestFit + blockSize;
        blockHeader* newBlock = (blockHeader*) nextHeader;

        //In this case, we must add size_status to newBlock
        //The size of the new split block will be the size of the best fiting block - what we allocated (size)
        newBlock->size_status = oldSize - size;

        //Change the pbit of the new split block to allocated and make sure that the allocated bit is 0.
        if (newBlock->size_status != 1) {
            newBlock->size_status = newBlock->size_status & ~1; //sets allocation bit to 0, meaning not allocated
            newBlock->size_status = newBlock->size_status | 2; //sets pbit to 1 signifying what it split from is allocated.
        }
    }

        //Return address of payload from where memory is allocated
        //cast as char* for scale factor
        void* toReturn = ((char*) bestFit) + sizeof(blockHeader);
        return toReturn;
    }

    //Should be unreachable but redundantly return NULL just in case.
    return NULL;
}

/*
 * Function for freeing up a previously allocated block.
 * Argument ptr: address of the block to be freed up.
 * Returns 0 on success.
 * Returns -1 on failure.
 * This function should:
 * - Return -1 if ptr is NULL.
 * - Return -1 if ptr is not a multiple of 8.
 * - Return -1 if ptr is outside of the heap space.
 * - Return -1 if ptr block is already freed.
 * - Update header(s) and footer as needed.
 */
int bfree(void *ptr) {
    //Return -1 if ptr is NULL
    if (ptr == NULL) {
        return -1;
    }

    //Return -1 if ptr is not a multiple of 8.
    //Casting the value of ptr to an unsigned int so that it can easily
    //be checked if ptr is not a multiple of 8
    unsigned int numPtr;
    numPtr = (unsigned int) ptr;
    if (numPtr % 8 != 0) {
        return -1;
    }

    //two things to consider:
    //1. if ptr is less than heap start
    //2. given alloc size, find end of allocated space and see if ptr is greater
    void* heapStart = heap_start;
    if (ptr < heapStart) {
        return -1;
    }

    void* endSpace = (char*) heap_start + alloc_size;
    if (ptr > endSpace) {
        return -1;
    }

    //The ptr address we are given is the address of the payload.
    //In order to look at the HDR information, we must go back by sizeof(blockHeader)
    //which will get us to the start of the blockHeader for this payload which contains size_status
    void* headerTemp = (char*) ptr - sizeof(blockHeader);
    blockHeader* header = (blockHeader*) headerTemp;

    //Return -1 if ptr block is already free (meaning abit of header of payload is set to 0)
    if ( (header->size_status & 1) == 0 ) {
        return -1;
    }

    //Now the variable header points to the header of the payload given from ptr pointer in parameter
    //Set the allocation bit (bit0) to be 0, indicating this is now free and NOT allocated
    header->size_status = header->size_status & ~1;

    //Take the size from the header and find the next header. If it is NOT the end block, then change
    //the p-bit to 0 since we have now freed it.
    //Must extract size from size_status and then advance that many bytes to find next
    //block header in memory
    //(next 3 lines are pretty much exactly what I did in balloc() also, look up there for explanations
    int blockSize = header->size_status & ~3;
    void* nextHeaderTemp = (char*)header + blockSize;
    blockHeader* nextHeader = (blockHeader*) nextHeaderTemp;

    //Set the pbit of the nextHeader to 0 (3 lines above are only to get location of next header)
   //ONLY IF the next block is not the end block. Don't want to cause an infinite loop again!
   if(nextHeader->size_status != 1) {
        nextHeader->size_status = nextHeader->size_status & ~2;
   }

    return 0;
}

/*
 * Function for traversing heap block list and coalescing all adjacent
 * free blocks.
 *
 * This function is used for user-called coalescing.
 * Updated header size_status and footer size_status as needed.
 */
int coalesce() {
    //Variable to use to traverse through heap block
    blockHeader* find = heap_start;
    int blockSize = 0;
    void* nextHeaderTemp = NULL;
    blockHeader* nextHeader = NULL;
    int coalesceCheck = 0;
    //Traverse through heap block list and coalesce adjacent free blocks
    //The algorithm I will use is starting at the start of the heap
    //and when a free block is found, coalesce with all of the next free blocks.

    //Start by traversing through heap block and stopping when reaching the end mark, similar to while loop in balloc().
    while ( find->size_status != 1) {
        //Check if the block we are at (find) is free or allocated by checking a-bit (bit0) = 0 or 1
        if ( (find->size_status & 1) == 0) {
                //Create variable which stores address of next header
                blockSize = find->size_status & ~3;
                nextHeaderTemp = (char*)find + blockSize;
                nextHeader = (blockHeader*) nextHeaderTemp;
                //While loop inside of other while loop, which is confusing
                //The purpose of this while loop is to keep finding every adjacent next free block
                //Also making sure that we do not go to an end block
                while ( ((nextHeader->size_status & 1) == 0) && nextHeader->size_status != 1) {
                        //Coalesce the nextHeader with find (header before it)
                        //When coalescing, make sure the pbit is the same as the old one
                        //Also make sure that alloc bit still indicates free
                        int oldPBit = -1;
                        if ( (find->size_status & 2) == 2) {
                                oldPBit = 1;
                        }
                        else {
                                oldPBit = 0;
                        }

                        //Change sizeStatus of find Header to be the size of both of the blocks we are coalescing
                        find->size_status = (find->size_status & ~3) + (nextHeader->size_status & ~3);
                        //Set pbit of size_status to original value and also make sure the allocated bit means free (=0).
                        //Change pbit to 0 like it was before.
                        if (oldPBit == 0) {
                                find->size_status = find->size_status & ~2;
                        }
                        //change pbit to 1
                        else {
                                find->size_status = find->size_status | 2;
                        }
                        //Chance allocated bit to 0 meaning it is free.
                        find->size_status = find->size_status & ~1;

                        //Update coalesceCheck variable to return positive integer since we coalesced
                        coalesceCheck = 1;

                        //Update to go to the nextHeader and continue checking for adjacent free blocks
                        blockSize = nextHeader->size_status & ~3;
                        nextHeaderTemp = (char*)nextHeader + blockSize;
                        nextHeader = (blockHeader*) nextHeaderTemp;
                }

                //Set find to the nextHeader once all adjacent free blocks have been found
                find = nextHeader;
        }
        //If the block we are at is not free, jump to next header and continue in while loop
        else {
                blockSize = find->size_status & ~3;
                nextHeaderTemp = (char*)find + blockSize;
                nextHeader = (blockHeader*) nextHeaderTemp;
                find = nextHeader;
                }
    }
    return coalesceCheck;
}

/*
 * Function used to initialize the memory allocator.
 * Intended to be called ONLY once by a program.
 * Argument sizeOfRegion: the size of the heap space to be allocated.
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int init_heap(int sizeOfRegion) {

    static int allocated_once = 0; //prevent multiple myInit calls

    int   pagesize; // page size
    int   padsize;  // size of padding when heap size not a multiple of page size
    void* mmap_ptr; // pointer to memory mapped area
    int   fd;

    blockHeader* end_mark;

    if (0 != allocated_once) {
        fprintf(stderr,
        "Error:heap.c: InitHeap has allocated space during a previous call\n");
        return -1;
    }

    if (sizeOfRegion <= 0) {
        fprintf(stderr, "Error:mem.c: Requested block size is not positive\n");
        return -1;
    }

    // Get the pagesize from O.S.
    pagesize = getpagesize();

    // Calculate padsize as the padding required to round up sizeOfRegion
    // to a multiple of pagesize
    padsize = sizeOfRegion % pagesize;
    padsize = (pagesize - padsize) % pagesize;

    alloc_size = sizeOfRegion + padsize;

    // Using mmap to allocate memory
    fd = open("/dev/zero", O_RDWR);
    if (-1 == fd) {
        fprintf(stderr, "Error:mem.c: Cannot open /dev/zero\n");
        return -1;
    }
    mmap_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == mmap_ptr) {
        fprintf(stderr, "Error:mem.c: mmap cannot allocate space\n");
        allocated_once = 0;
        return -1;
    }

    allocated_once = 1;

    // for double word alignment and end mark
    alloc_size -= 8;

    // Initially there is only one big free block in the heap.
    // Skip first 4 bytes for double word alignment requirement.
    heap_start = (blockHeader*) mmap_ptr + 1;

    // Set the end mark
    end_mark = (blockHeader*)((void*)heap_start + alloc_size);
    end_mark->size_status = 1;

    // Set size in header
    heap_start->size_status = alloc_size;

    // Set p-bit as allocated in header
    // note a-bit left at 0 for free
    heap_start->size_status += 2;

     // Set the footer
    blockHeader *footer = (blockHeader*) ((void*)heap_start + alloc_size - 4);
    footer->size_status = alloc_size;

    return 0;
}

/*
 * Function can be used to visualize the heap structure.
 * Traverses heap blocks and prints info about each block found.
 *
 * Prints out a list of all the blocks including this information:
 * No.      : serial number of the block
 * Status   : free/used (allocated)
 * Prev     : status of previous block free/used (allocated)
 * t_Begin  : address of the first byte in the block (where the header starts)
 * t_End    : address of the last byte in the block
 * t_Size   : size of the block as stored in the block header
 */
void disp_heap() {

    int    counter;
    char   status[6];
    char   p_status[6];
    char * t_begin = NULL;
    char * t_end   = NULL;
    int    t_size;

    blockHeader *current = heap_start;
    counter = 1;

    int used_size =  0;
    int free_size =  0;
    int is_used   = -1;

    fprintf(stdout,
        "*********************************** HEAP: Block List ****************************\n");
    fprintf(stdout, "No.\tStatus\tPrev\tt_Begin\t\tt_End\t\tt_Size\n");
    fprintf(stdout,
        "---------------------------------------------------------------------------------\n");

    while (current->size_status != 1) {
        t_begin = (char*)current;
        t_size = current->size_status;

        if (t_size & 1) {
            // LSB = 1 => used block
            strcpy(status, "alloc");
            is_used = 1;
            t_size = t_size - 1;
        } else {
            strcpy(status, "FREE ");
            is_used = 0;
        }
        if (t_size & 2) {
            strcpy(p_status, "alloc");
            t_size = t_size - 2;
        } else {
            strcpy(p_status, "FREE ");
        }

        if (is_used)
            used_size += t_size;
        else
            free_size += t_size;

        t_end = t_begin + t_size - 1;

        fprintf(stdout, "%d\t%s\t%s\t0x%08lx\t0x%08lx\t%4i\n", counter, status,
        p_status, (unsigned long int)t_begin, (unsigned long int)t_end, t_size);

        current = (blockHeader*)((char*)current + t_size);
        counter = counter + 1;
    }

    fprintf(stdout,
        "---------------------------------------------------------------------------------\n");
    fprintf(stdout,
    "---------------------------------------------------------------------------------\n");
    fprintf(stdout,
        "*********************************************************************************\n");
    fprintf(stdout, "Total used size = %4d\n", used_size);
    fprintf(stdout, "Total free size = %4d\n", free_size);
    fprintf(stdout, "Total size      = %4d\n", used_size + free_size);
    fprintf(stdout,
        "*********************************************************************************\n");
    fflush(stdout);

    return;
}

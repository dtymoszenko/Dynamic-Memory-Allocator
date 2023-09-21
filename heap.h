#ifndef heap_h
#define heap_h

int   init_heap(int sizeOfRegion);
void  disp_heap();

void* balloc(int size);
int   bfree(void *ptr);
int   coalesce();

void* malloc(size_t size) {
    return NULL;
}

#endif

/**
 * @file no_heap_wrap.c
 * @brief GNU ld --wrap=malloc / newlib _malloc_r 등 동적 힙 호출 시 트랩 (빌드 인프라)
 *
 * HTS_ARM_ENFORCE_NO_HEAP_LINK=ON 일 때만 링크됩니다.
 * 코어 알고리즘 TU는 수정하지 않으며, 링크 정책으로만 힙 사용을 차단합니다.
 *
 * @note newlib 초기화·stdio 버퍼 등이 힙을 쓰는 구성이면 부팅 전 트랩될 수 있으므로,
 *       해당 경우 CMake에서 HTS_ARM_ENFORCE_NO_HEAP_LINK=OFF 로 완화하십시오.
 */

#include <stddef.h>
#include <sys/reent.h>

__attribute__((noreturn)) static void hts_no_heap_trap(void)
{
    for (;;) {
#if defined(__thumb__) && (defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__))
        __asm volatile ("bkpt #0" ::: "memory");
#else
        __asm volatile ("" ::: "memory");
#endif
    }
}

void *__wrap_malloc(size_t size)
{
    (void)size;
    hts_no_heap_trap();
}

void *__wrap__malloc_r(struct _reent *reent, size_t nbytes)
{
    (void)reent;
    (void)nbytes;
    hts_no_heap_trap();
}

void *__wrap_calloc(size_t n, size_t s)
{
    (void)n;
    (void)s;
    hts_no_heap_trap();
}

void *__wrap__calloc_r(struct _reent *reent, size_t n, size_t s)
{
    (void)reent;
    (void)n;
    (void)s;
    hts_no_heap_trap();
}

void *__wrap_realloc(void *p, size_t s)
{
    (void)p;
    (void)s;
    hts_no_heap_trap();
}

void *__wrap__realloc_r(struct _reent *reent, void *p, size_t s)
{
    (void)reent;
    (void)p;
    (void)s;
    hts_no_heap_trap();
}

void __wrap_free(void *p)
{
    (void)p;
    hts_no_heap_trap();
}

void __wrap__free_r(struct _reent *reent, void *p)
{
    (void)reent;
    (void)p;
    hts_no_heap_trap();
}

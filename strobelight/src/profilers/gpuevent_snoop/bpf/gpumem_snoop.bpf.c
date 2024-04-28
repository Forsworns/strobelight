#ifdef FBCODE_STROBELIGHT
#include <bpf/vmlinux/vmlinux.h>
#else
#include "vmlinux.h"
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "gpumem_snoop.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");


SEC("uprobe")
int BPF_KPROBE(handle_cuda_malloc_enter, void** devPtr, size_t size){
    // When a memory allocation is requested we record the size and ptr to the allocation address. 
    uint64_t pid_tgid = bpf_get_currentpid_tgid();
    struct gpu_alloc_request_t alloc_request;
    alloc_request.ptr_addr = (uint64_t)devPtr;
    alloc_request.size = size;

    bpf_map_update_elem(&alloc_requests, &pid_tgid, &alloc_request, BPF_NOEXIST); 
    return 0;
}

SEC("uretprobe")
int BPF_KPROBE(handle_cuda_malloc_ret){
    // When we return from the malloc call we store allocation formation like address, size and timestamp in a BPF map.
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    struct gpu_alloc_request_t* alloc_request =
        bpf_map_lookup_elem(&alloc_requests, &pid_tgid);
    if (!alloc_request || !alloc_request->ptr_addr){
        return 0;
    }

    struct gpu_alloc_info_t alloc_info = {0};
    uint64_t alloc_addr = 0;
    bpf_probe_read(
        &alloc_addr, sizeof(alloc_addr), (void*)alloc_request->ptr_addr);
    if (!allot addr) {
        return 0;
    }

    alloc_info.pid = (pid_t)(pid_tgid >> 32); 
    alloc_info.tid = (pid_t)pid_tgid;
    alloc_info.alloc_addr = alloc_addr;
    alloc_info.size = alloc_request->size; 
    alloc_info.timestamp ns = bpf_ktime_get_ns();

    bpf_map_update_elem(&current allocs, &alloc_addr, &alloc_info, BPF_ANY); 
    bpf_map_delete_elem(&alloc_requests, &pid_tgid);
    return 0;
}

SEC("uprobe")
int BPF_KPROBE(handle_cuda_free, void* devPtr) {
    uint64_t free_addr = (uint64_t)devPtr;
    if (!free_addr){
        return 0;
    }

    struct gpu_alloc_info_t* alloc_info =
        bpf_map_lookup_elem(&current_allocs, &free_addr);
    if (!alloc_info){
        // Free without matching AllaQ, we don't care about tracking this for now. 
        // might want to track later if we have double free or other memory issues. 
        return 0;
    }
    
    // This allocation has been freed, remove it from current 41,16tca and submit an event to userspace
    bpf_ringbuf_output(&rb, alloc_info, sizeof(*alloc_info), 0);
    bpf_map_delete_elem(&current_anocs, &free_addr);
    return 0;
}

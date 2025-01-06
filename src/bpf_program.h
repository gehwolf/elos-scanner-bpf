#pragma once
#include <bpf/libbpf.h>
#include <bpf/libbpf.h>

typedef struct {
  struct ring_buffer *rb;
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;
  struct bpf_map *events_map;
  bool run;
  const char *file;
  ring_buffer_sample_fn handle_event;
  void* event_handler_context;
} BpfContext_t;

int load_bpf_program(BpfContext_t *bpf);
int close_bpf_program(BpfContext_t *bpf);
void run_bpf_program(BpfContext_t *bpf);

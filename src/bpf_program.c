#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>

#include "bpf_program.h"


int load_bpf_program( BpfContext_t *bpf) {
  struct bpf_object *obj = NULL;
  int err = 0;

  struct bpf_object_open_opts opts = {
      .sz = sizeof(opts),
      .relaxed_maps = true,
  };

  // Load the precompiled BPF program
  obj = bpf_object__open_file(bpf->file, &opts);
  if (!obj) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
    return -1;
  }

  // Load the BPF program into the kernel
  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
    bpf_object__close(obj);
    return -1;
  }

  printf("BPF program loaded successfully.\n");

  // Attach the BPF program to a tracepoint
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "trace_socket_event");
  if (!prog) {
    fprintf(stderr, "Failed to find program\n");
    bpf_object__close(obj);
    return -1;
  }

  struct bpf_link *link =
      bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_socket");
  if (link == NULL) {
    fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
    bpf_object__close(obj);
    return -1;
  }

  struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
  if (events_map == NULL) {
    fprintf(stderr, "Failed to find 'events' map in BPF object\n");
    bpf_object__close(obj);
    return -1;
  }

  // Set up ring buffer
  struct ring_buffer *rb =
      ring_buffer__new(bpf_map__fd(events_map), bpf->handle_event, bpf->event_handler_context, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    bpf_object__close(obj);
    return -1;
  }

  printf("BPF program attached successfully.\n");

  bpf->obj = obj;
  bpf->events_map = events_map;
  bpf->prog = prog;
  bpf->link = link;
  bpf->rb = rb;

  return 0;
}

int close_bpf_program(BpfContext_t *bpf) {
  ring_buffer__free(bpf->rb);
  bpf_program__unload(bpf->prog);
  bpf_object__close(bpf->obj);
  return 0;
}

void run_bpf_program(BpfContext_t *bpf) {
  while (bpf->run) {
    int err = ring_buffer__poll(bpf->rb, 100);
    if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
    }
  }
}

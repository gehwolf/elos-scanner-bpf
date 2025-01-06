#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>

#include "bpf_program.h"
#include <elos/event/event_types.h>

static int handle_event(void *ctx, void *data, size_t data_sz) {
  elosEvent_t *event = data;
  printf("new event: %u s(%u) c(%lu) pid=%u\n", event->messageCode,
         event->severity, event->classification, event->source.pid);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "%s <path to compiled bpf>", argv[0]);
    return EXIT_FAILURE;
  }

  printf("Starting BPF program...\n");
  BpfContext_t bpf_context = {
      .run = true,
      .file = argv[1],
      .handle_event = handle_event,
  };
  if (load_bpf_program(&bpf_context) == 0) {
    printf("BPF program loaded successfully.\n");
  } else {
    printf("Failed to load BPF program.\n");
  }

  printf("Monitoring socket events... Press Ctrl+C to stop.\n");
  run_bpf_program(&bpf_context);

  return 0;
}

#include <elos/event/event_classification.h>
#include <elos/event/event_message_codes.h>
#include <elos/event/event_severity.h>
#include <elos/event/event_types.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <elos/event/event.h>
#include <linux/ptrace.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 12); // 4 KB buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_event(struct pt_regs *ctx) {

  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  char format_string[] = "Socket syscall detected: PID=%u\n";
  bpf_trace_printk(format_string, sizeof(format_string), pid);

  elosEvent_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    bpf_printk("failed to allocate event in ringbufer");
    return 0;
  }

  memset(event, 0, sizeof(elosEvent_t));

  event->messageCode = ELOS_MSG_CODE_SOCKET_OPENEND;
  event->source.pid = pid;
  event->severity = ELOS_SEVERITY_INFO;
  event->classification = ELOS_CLASSIFICATION_NETWORK;

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";

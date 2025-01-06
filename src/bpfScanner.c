// SPDX-License-Identifier: MIT

#include <elos/libelosplugin/libelosplugin.h>
#include <safu/common.h>
#include <safu/log.h>
#include <stdlib.h>

#include "bpf_program.h"

static int handle_event(void *ctx, void *data, size_t data_sz);

static safuResultE_t _pluginLoad(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    if ((plugin->config == NULL) || (plugin->config->key == NULL)) {
      safuLogErr("Given configuration is NULL or has .key set to NULL");
    } else {
      plugin->data = safuAllocMem(NULL, sizeof(BpfContext_t));

      safuLogDebugF("Scanner Dummy Plugin '%s' has been loaded",
                    plugin->config->key);
      result = SAFU_RESULT_OK;
    }
  }

  return result;
}

static safuResultE_t _pluginStart(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {

    BpfContext_t *bpf_context = plugin->data;
    bpf_context->file = "/usr/lib/elos/scanner/socket.bpf.o";
    bpf_context->run = true;
    bpf_context->handle_event = handle_event;
    bpf_context->event_handler_context = plugin;
    if (load_bpf_program(bpf_context) == 0) {
      safuLogDebugF("Scanner BPF Plugin '%s' has been started",
                    plugin->config->key);
      result = elosPluginReportAsStarted(plugin);
      if (result == SAFU_RESULT_FAILED) {
        safuLogErr("elosPluginReportAsStarted failed");
      } else {
        run_bpf_program(bpf_context);
        result = elosPluginStopTriggerWait(plugin);
        if (result == SAFU_RESULT_FAILED) {
          safuLogErr("elosPluginStopTriggerWait failed");
        }
      }
    } else {
      safuLogErr("Failed to load BPF program.\n");
    }
  }

  return result;
}

static safuResultE_t _pluginStop(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    safuLogDebugF("Stopping Scanner Dummy Plugin '%s'", plugin->config->key);

    BpfContext_t *bpf_context = plugin->data;
    bpf_context->run = false;
    result = elosPluginStopTriggerWrite(plugin);
    if (result == SAFU_RESULT_FAILED) {
      safuLogErr("elosPluginStopTriggerWrite failed");
    }
  }

  return result;
}

static safuResultE_t _pluginUnload(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    safuLogDebugF("Unloading Scanner Dummy Plugin '%s'", plugin->config->key);

    BpfContext_t *bpf_context = plugin->data;
    close_bpf_program(bpf_context);
    free(plugin->data);
    result = SAFU_RESULT_OK;
  }

  return result;
}

elosPluginConfig_t elosPluginConfig = {
    .type = PLUGIN_TYPE_SCANNER,
    .load = _pluginLoad,
    .unload = _pluginUnload,
    .start = _pluginStart,
    .stop = _pluginStop,
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
  elosPlugin_t *plugin = ctx;
  elosEvent_t *event = data;
  struct elosPublisher *publisher = NULL;
  safuResultE_t result = elosPluginCreatePublisher(plugin, &publisher);

  safuLogDebugF("new event: %u s(%u) c(%lu) pid=%u\n", event->messageCode,
                event->severity, event->classification, event->source.pid);
  if (result == SAFU_RESULT_FAILED) {
    safuLogErr("elosPluginCreatePublisher failed");
  } else {
    result = elosPluginPublish(plugin, publisher, event);
    if (result != SAFU_RESULT_OK) {
      safuLogErr("elosPluginPublish failed");
    }
  }
  return 0;
}

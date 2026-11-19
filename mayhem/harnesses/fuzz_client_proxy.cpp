/*
 * Server side of the deskflow wire protocol: bytes a (malicious) CLIENT sends to the server.
 *
 * The server greets every new connection with ClientProxyUnknown (server/ClientProxyUnknown.cpp),
 * which parses the hello reply (protocol name, version, client name), creates the ClientProxy1_0..1_8
 * for that version, and that proxy then parses every later message (DINF screen info, CCLP/DCLP
 * clipboard incl. chunk assembly + Clipboard::unmarshall, keep-alives, LSYN, ...). The input is the raw
 * TCP byte stream, framed by PacketStreamFilter as the real listener does (server/ClientListener.cpp).
 */
#include "fuzz_common.h"

#include "base/BaseException.h"
#include "deskflow/Computer.h"
#include "deskflow/OptionTypes.h"
#include "deskflow/PacketStreamFilter.h"
#include "server/ClientProxy.h"
#include "server/ClientProxyUnknown.h"
#include "server/Config.h"
#include "server/PrimaryClient.h"
#include "server/Server.h"

#include <memory>

namespace {

// The server the proxies talk to. The proxies only read its protocol name and clipboard size limit,
// which no input can change, so one instance is shared by every input.
struct ServerEnv
{
  mayhem::SyncEventQueue events;
  // the Computer owns (deletes) its platform
  deskflow::Computer computer{new mayhem::StubPlatformComputer(&events, true), &events};
  deskflow::server::Config config{&events};
  std::unique_ptr<PrimaryClient> primary;
  std::unique_ptr<Server> server;

  ServerEnv()
  {
    config.addComputer("fuzz-server");
    // no built-in ScrollLock hotkey: its setup in Server::setConfig frees a malloc()ed KeyInfo with
    // delete (an ASan alloc-dealloc-mismatch at start-up, unrelated to client input)
    config.addOption("", kOptionDisableLockToComputer, 1);
    primary = std::make_unique<PrimaryClient>("fuzz-server", &computer);
    server = std::make_unique<Server>(config, primary.get(), &computer, &events);
    events.discard();
  }
};

ServerEnv *g_env = nullptr;

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  g_env = new ServerEnv;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (g_env == nullptr) {
    mayhem::initOnce();
    g_env = new ServerEnv;
  }
  auto &events = g_env->events;

  bool alive = false;
  auto *raw = new mayhem::FakeStream(std::string(reinterpret_cast<const char *>(data), size), &alive);
  auto *stream = new PacketStreamFilter(&events, raw, true);
  // owns the stream (and, once the hello is parsed, the proxy that took it over)
  auto unknown = std::make_unique<ClientProxyUnknown>(stream, 30.0, g_env->server.get(), &events);

  try {
    // socket readable: the filter frames the bytes and wakes the hello parser
    events.dispatchEvent(Event(deskflow::EventTypes::StreamInputReady, raw->getEventTarget()));
    events.drain();
    // the hello parser consumes one message; the proxy it created parses the rest when the
    // stream signals readiness again (a disconnect deletes the proxy and its stream)
    for (int i = 0; i < 4 && alive && stream->isReady(); ++i) {
      events.dispatchEvent(Event(deskflow::EventTypes::StreamInputReady, stream->getEventTarget()));
      events.drain();
    }
  } catch (const BaseException &) {
    // protocol/IO errors surface as deskflow exceptions; the server drops the client
  }

  events.discard();
  // like Server::handleClientProxyUnknownSuccess: take the finished proxy, then destroy it
  std::unique_ptr<ClientProxy> proxy(unknown->orphanClientProxy());
  proxy.reset();
  unknown.reset();
  // deliver the IPC notifications the server queued (no IPC client is connected), so they don't
  // pile up in the Qt event queue across inputs
  QCoreApplication::sendPostedEvents();
  return 0;
}

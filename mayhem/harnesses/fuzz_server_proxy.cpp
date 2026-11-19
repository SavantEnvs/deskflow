/*
 * Client side of the deskflow wire protocol: bytes a (malicious) SERVER sends to a connected client.
 *
 * The harness drives a real Client through its production connect path: Client::connect() asks the
 * socket factory for a data socket (here an in-memory one holding the input), wraps it in
 * PacketStreamFilter, and on the socket's "connected" event runs Client::handleConnected (which
 * resets the client's clipboard state). The input is the raw TCP byte stream from the server
 * (4-byte big-endian length + message), starting with the server's hello; Client::handleHello picks
 * the ServerProxy for the negotiated version (1.6 = ServerProxy, 1.7, 1.8) and every following
 * message goes to it. Reaches hello parsing, handshake/message parsing, ProtocolUtil::readf, DCLP
 * clipboard chunk assembly + Clipboard::unmarshall, DSOP options and LSYN keyboard layouts.
 */
#include "fuzz_common.h"

#include "base/BaseException.h"
#include "client/Client.h"
#include "deskflow/Computer.h"
#include "net/IDataSocket.h"
#include "net/ISocketFactory.h"
#include "net/NetworkAddress.h"

#include <QCoreApplication>

#include <memory>

namespace {

// A connected TCP socket whose peer already sent the input bytes. Reads drain them; writes (our
// replies) are dropped. connect() reports success the way TCPSocket/SecureSocket do: by queueing
// the connected event on the socket's target.
class FakeDataSocket : public IDataSocket
{
public:
  FakeDataSocket(IEventQueue *events, std::string bytes) : IDataSocket(events), m_events(events), m_data(std::move(bytes))
  {
  }

  // ISocket
  void bind(const NetworkAddress &) override
  {
  }
  void close() override
  {
    m_data.clear();
    m_pos = 0;
    m_inputShutdown = true;
  }
  void *getEventTarget() const override
  {
    return const_cast<FakeDataSocket *>(this);
  }

  // IDataSocket
  void connect(const NetworkAddress &) override
  {
    // plain TCP signals DataSocketConnected, TLS signals DataSocketSecureConnected after its
    // handshake; the client listens for exactly one of them (Settings TlsEnabled)
    m_events->addEvent(Event(deskflow::EventTypes::DataSocketConnected, getEventTarget()));
    m_events->addEvent(Event(deskflow::EventTypes::DataSocketSecureConnected, getEventTarget()));
  }
  bool isFatal() const override
  {
    return false;
  }

  // IStream
  uint32_t read(void *buffer, uint32_t size) override
  {
    if (m_inputShutdown || size == 0)
      return 0;
    const size_t n = std::min<size_t>(size, m_data.size() - m_pos);
    if (n == 0)
      return 0;
    if (buffer != nullptr)
      std::memcpy(buffer, m_data.data() + m_pos, n);
    m_pos += n;
    return static_cast<uint32_t>(n);
  }
  void write(const void *, uint32_t) override
  {
  }
  void flush() override
  {
  }
  void shutdownInput() override
  {
    close();
  }
  void shutdownOutput() override
  {
  }
  bool isReady() const override
  {
    return !m_inputShutdown && m_pos < m_data.size();
  }
  uint32_t getSize() const override
  {
    return m_inputShutdown ? 0 : static_cast<uint32_t>(m_data.size() - m_pos);
  }

private:
  IEventQueue *m_events;
  std::string m_data;
  size_t m_pos = 0;
  bool m_inputShutdown = false;
};

// Client owns (and deletes) its socket factory. It creates one socket per connect(): the input.
class InputSocketFactory : public ISocketFactory
{
public:
  InputSocketFactory(IEventQueue *events, std::string bytes, FakeDataSocket **created)
      : m_events(events),
        m_bytes(std::move(bytes)),
        m_created(created)
  {
  }
  IDataSocket *create(IArchNetwork::AddressFamily, SecurityLevel) const override
  {
    auto *socket = new FakeDataSocket(m_events, m_bytes);
    *m_created = socket;
    return socket;
  }
  IListenSocket *createListen(IArchNetwork::AddressFamily, SecurityLevel) const override
  {
    return nullptr;
  }

private:
  IEventQueue *m_events;
  std::string m_bytes;
  FakeDataSocket **m_created;
};

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  mayhem::initOnce();
  if (size < 1)
    return -1;

  mayhem::SyncEventQueue events;
  // the Computer owns (deletes) its platform
  auto computer = std::make_unique<deskflow::Computer>(new mayhem::StubPlatformComputer(&events, false), &events);
  FakeDataSocket *socket = nullptr;
  auto client = std::make_unique<Client>(
      &events, "fuzz-client", NetworkAddress("127.0.0.1", 24800),
      new InputSocketFactory(&events, std::string(reinterpret_cast<const char *>(data), size), &socket),
      computer.get()
  );

  try {
    // Client::connect creates the socket and its PacketStreamFilter; the socket's connected event
    // runs Client::handleConnected
    client->connect();
    events.drain();
    // the server's bytes arrive: the filter frames them, Client::handleHello reads the hello and
    // creates the ServerProxy, which parses every following complete message. The client owns the
    // socket and may delete it while handling events, so it is not touched after this dispatch.
    if (socket != nullptr && client->isConnecting()) {
      events.dispatchEvent(Event(deskflow::EventTypes::StreamInputReady, socket->getEventTarget()));
      events.drain();
    }
  } catch (const BaseException &) {
    // protocol/IO errors surface as deskflow exceptions; the client drops the connection
  }

  events.discard();
  client.reset();
  computer.reset();
  // deliver the IPC notifications the client queued (no IPC client is connected), so they don't
  // pile up in the Qt event queue across inputs
  QCoreApplication::sendPostedEvents();
  return 0;
}

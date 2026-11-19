/*
 * Shared environment for the deskflow fuzz harnesses (Mayhem integration).
 *
 * Everything here mocks the ENVIRONMENT the parsers run in (an in-memory stream instead of a
 * socket, a synchronous event queue instead of the threaded one, a do-nothing platform instead of
 * X11/libei). The parsing code under test is deskflow's own, linked from the project libraries.
 * The fakes follow upstream's unit tests (src/unittests/client/ServerProxyTests.cpp,
 * src/unittests/server/ClientProxyTests.cpp).
 */
#pragma once

#include "arch/Arch.h"
#include "base/Event.h"
#include "base/IEventQueue.h"
#include "base/Log.h"
#include "common/LogLevel.h"
#include "deskflow/AppUtil.h"
#include "deskflow/IPlatformComputer.h"
#include "deskflow/ipc/CoreIpcServer.h"
#include "io/IStream.h"

#include <QCoreApplication>
#include <QDir>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

namespace mayhem {

// AppUtil is a process singleton (AppUtil::instance()); KeyboardLayoutManager asks it for the local
// keyboard layouts. Fixed answer, so every input sees the same local layouts.
class FuzzAppUtil : public AppUtil
{
public:
  int run() override
  {
    return 0;
  }
  std::vector<std::string> getKeyboardLayoutList() override
  {
    return {"en", "de", "fr"};
  }
  std::string getCurrentLanguageCode() override
  {
    return "en";
  }
};

// One-time process setup: Qt core app (QString/QSettings need it), a quiet Log singleton (LOG_* needs
// one), the AppUtil singleton, the core IPC server singleton, and a private, empty settings/state directory so the Settings
// singleton never reads the host user's deskflow config (each input sees default settings).
inline void initOnce()
{
  static bool done = false;
  if (done)
    return;
  done = true;

  const char *tmp = getenv("TMPDIR");
  std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/deskflow-fuzz-XXXXXX";
  std::vector<char> dir(tmpl.begin(), tmpl.end());
  dir.push_back('\0');
  if (mkdtemp(dir.data()) != nullptr) {
    setenv("XDG_CONFIG_HOME", dir.data(), 1);
    setenv("XDG_STATE_HOME", dir.data(), 1);
    setenv("HOME", dir.data(), 1);
  }
  setenv("QT_QPA_PLATFORM", "offscreen", 1);

  static int argc = 1;
  static char arg0[] = "deskflow-fuzz";
  static char *argv[] = {arg0, nullptr};
  static QCoreApplication app(argc, argv);

  static Arch arch; // ARCH singleton (network address helpers)
  static Log log;
  log.setFilter(LogLevel::Level::Fatal);
  static FuzzAppUtil appUtil;
  // deskflow-core creates the CoreIpcServer singleton before any protocol traffic
  // (src/apps/deskflow-core/deskflow-core.cpp); Client/Server/ServerProxy1_8 notify the GUI through
  // CoreIpcServer::instance(). Not listening: no IPC client ever connects, so the queued broadcasts
  // (delivered by QCoreApplication::sendPostedEvents after each input) go nowhere.
  static deskflow::core::ipc::CoreIpcServer ipcServer(&app);
}

// In-memory stream holding the bytes the peer sent. Reads drain it; writes (our replies) are dropped.
class FakeStream : public deskflow::IStream
{
public:
  explicit FakeStream(std::string bytes, bool *alive = nullptr) : m_data(std::move(bytes)), m_alive(alive)
  {
    if (m_alive != nullptr)
      *m_alive = true;
  }
  // an owner (PacketStreamFilter, ClientProxy) may delete the stream mid-run; *alive tells the harness
  ~FakeStream() override
  {
    if (m_alive != nullptr)
      *m_alive = false;
  }

  void close() override
  {
    m_data.clear();
    m_pos = 0;
    m_inputShutdown = true;
  }

  uint32_t read(void *buffer, uint32_t size) override
  {
    if (m_inputShutdown || size == 0)
      return 0;
    const size_t left = m_data.size() - m_pos;
    const size_t n = std::min<size_t>(size, left);
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
  void *getEventTarget() const override
  {
    return const_cast<FakeStream *>(this);
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
  std::string m_data;
  size_t m_pos = 0;
  bool m_inputShutdown = false;
  bool *m_alive = nullptr;
};

// Synchronous event queue with the dispatch rules of base/EventQueue.cpp: a (type, target) handler,
// else the target's catch-all (EventTypes::Unknown) handler. Queued events are delivered by drain().
class SyncEventQueue : public IEventQueue
{
public:
  ~SyncEventQueue() override
  {
    discard();
  }

  int loop() override
  {
    return 0;
  }
  void adoptBuffer(IEventQueueBuffer *) override
  {
  }
  bool getEvent(Event &, double = -1.0) override
  {
    return false;
  }

  bool dispatchEvent(const Event &event) override
  {
    auto it = m_handlers.find(Key{event.getType(), event.getTarget()});
    if (it == m_handlers.end())
      it = m_handlers.find(Key{deskflow::EventTypes::Unknown, event.getTarget()});
    if (it == m_handlers.end())
      return false;
    const auto handler = it->second; // the handler may remove itself
    handler(event);
    return true;
  }

  void addEvent(Event &&event) override
  {
    switch (event.getType()) {
    case deskflow::EventTypes::Unknown:
    case deskflow::EventTypes::System:
    case deskflow::EventTypes::Timer:
      Event::deleteData(event);
      return;
    default:
      m_pending.emplace_back(std::move(event));
    }
  }

  // Deliver queued events (bounded: a handler may queue more).
  void drain(int budget = 256)
  {
    while (!m_pending.empty() && budget-- > 0) {
      Event e = std::move(m_pending.front());
      m_pending.pop_front();
      dispatchEvent(e);
      Event::deleteData(e);
    }
  }

  void discard()
  {
    for (auto &e : m_pending)
      Event::deleteData(e);
    m_pending.clear();
  }

  EventQueueTimer *newTimer(double, void *) override
  {
    return timer();
  }
  EventQueueTimer *newOneShotTimer(double, void *) override
  {
    return timer();
  }
  void deleteTimer(EventQueueTimer *) override
  {
  }

  void addHandler(deskflow::EventTypes type, void *target, const EventHandler &handler) override
  {
    m_handlers[Key{type, target}] = handler;
  }
  void removeHandler(deskflow::EventTypes type, void *target) override
  {
    m_handlers.erase(Key{type, target});
  }
  void removeHandlers(void *target) override
  {
    for (auto it = m_handlers.begin(); it != m_handlers.end();) {
      if (it->first.target == target)
        it = m_handlers.erase(it);
      else
        ++it;
    }
  }
  void waitForReady() const override
  {
  }
  void *getSystemTarget() override
  {
    return this;
  }

private:
  EventQueueTimer *timer()
  {
    return reinterpret_cast<EventQueueTimer *>(&m_timerStorage);
  }

  struct Key
  {
    deskflow::EventTypes type;
    void *target;
    bool operator<(const Key &o) const
    {
      if (type != o.type)
        return static_cast<uint32_t>(type) < static_cast<uint32_t>(o.type);
      return std::less<void *>{}(target, o.target);
    }
  };

  int m_timerStorage = 0;
  std::map<Key, EventHandler> m_handlers;
  std::deque<Event> m_pending;
};

// A platform with no display: a fixed 1920x1080 screen, no keys down, every fake-input call ignored.
// Clipboards set by the peer are kept so getClipboard() returns them.
class StubPlatformComputer : public IPlatformComputer
{
public:
  StubPlatformComputer(const IEventQueue *events, bool primary) : IPlatformComputer(events), m_primary(primary)
  {
  }

  // IComputer
  void *getEventTarget() const override
  {
    return const_cast<StubPlatformComputer *>(this);
  }
  bool getClipboard(ClipboardID, IClipboard *) const override
  {
    return false;
  }
  void getShape(int32_t &x, int32_t &y, int32_t &w, int32_t &h) const override
  {
    x = 0;
    y = 0;
    w = 1920;
    h = 1080;
  }
  void getCursorPos(int32_t &x, int32_t &y) const override
  {
    x = 960;
    y = 540;
  }

  // IPrimaryComputer
  void reconfigure(uint32_t) override
  {
  }
  uint32_t activeSides() override
  {
    return 0;
  }
  void warpCursor(int32_t, int32_t) override
  {
  }
  uint32_t registerHotKey(KeyID, KeyModifierMask) override
  {
    return ++m_hotkeys;
  }
  void unregisterHotKey(uint32_t) override
  {
  }
  void fakeInputBegin() override
  {
  }
  void fakeInputEnd() override
  {
  }
  int32_t getJumpZoneSize() const override
  {
    return 1;
  }
  bool isAnyMouseButtonDown(uint32_t &buttonID) const override
  {
    buttonID = 0;
    return false;
  }
  void getCursorCenter(int32_t &x, int32_t &y) const override
  {
    x = 960;
    y = 540;
  }

  // ISecondaryComputer
  void fakeMouseButton(ButtonID, bool) override
  {
  }
  void fakeMouseMove(int32_t, int32_t) override
  {
  }
  void fakeMouseRelativeMove(int32_t, int32_t) const override
  {
  }
  void fakeMouseWheel(ScrollDelta) const override
  {
  }

  // IKeyState
  void updateKeyMap() override
  {
  }
  void updateKeyState() override
  {
  }
  void setHalfDuplexMask(KeyModifierMask) override
  {
  }
  void fakeKeyDown(KeyID, KeyModifierMask, KeyButton, const std::string &) override
  {
  }
  bool fakeKeyRepeat(KeyID, KeyModifierMask, int32_t, KeyButton, const std::string &) override
  {
    return true;
  }
  bool fakeKeyUp(KeyButton) override
  {
    return true;
  }
  void fakeAllKeysUp() override
  {
  }
  bool fakeCtrlAltDel() override
  {
    return true;
  }
  bool fakeMediaKey(KeyID) override
  {
    return true;
  }
  bool isKeyDown(KeyButton) const override
  {
    return false;
  }
  KeyModifierMask getActiveModifiers() const override
  {
    return 0;
  }
  KeyModifierMask pollActiveModifiers() const override
  {
    return 0;
  }
  int32_t pollActiveGroup() const override
  {
    return 0;
  }
  void pollPressedKeys(KeyButtonSet &) const override
  {
  }

  // IPlatformComputer
  void enable() override
  {
  }
  void disable() override
  {
  }
  void enter() override
  {
  }
  bool canLeave() override
  {
    return true;
  }
  void leave() override
  {
  }
  bool setClipboard(ClipboardID, const IClipboard *) override
  {
    return true;
  }
  void checkClipboards() override
  {
  }
  void openScreensaver(bool) override
  {
  }
  void closeScreensaver() override
  {
  }
  void screensaver(bool) override
  {
  }
  void resetOptions() override
  {
  }
  void setOptions(const OptionsList &) override
  {
  }
  void setSequenceNumber(uint32_t) override
  {
  }
  std::string getSecureInputApp() const override
  {
    return {};
  }
  bool isPrimary() const override
  {
    return m_primary;
  }
  void handleSystemEvent(const Event &) override
  {
  }

private:
  bool m_primary;
  uint32_t m_hotkeys = 0;
};

} // namespace mayhem

/*
 * The server configuration file (deskflow-server.conf / the GUI's exported config): sections
 * screens/aliases/links/options, keystroke()/mousebutton() conditions and actions, intervals and
 * options, parsed by `istream >> deskflow::server::Config` (server/Config.cpp). An accepted config is
 * written back out and must parse again.
 */
#include "fuzz_common.h"

#include "base/BaseException.h"
#include "server/Config.h"

#include <cstdlib>
#include <sstream>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  mayhem::SyncEventQueue events;
  deskflow::server::Config config(&events);
  std::istringstream in(std::string(reinterpret_cast<const char *>(data), size));
  try {
    in >> config;
  } catch (const BaseException &) {
    // ServerConfigReadException: the documented rejection of a bad file
    return 0;
  }

  std::ostringstream out;
  out << config;
  deskflow::server::Config reread(&events);
  std::istringstream in2(out.str());
  try {
    in2 >> reread;
  } catch (const BaseException &) {
    // the server wrote a config it cannot read back
    abort();
  }
  return 0;
}

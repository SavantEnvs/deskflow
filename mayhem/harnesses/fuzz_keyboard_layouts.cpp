/*
 * LSYN payload: the keyboard layout list a peer announces (protocol 1.8), parsed by
 * KeyboardLayoutManager::setRemoteLayouts (deskflow/KeyboardLayoutManager.cpp) into 2-letter codes and
 * compared with the local layouts, as ServerProxy1_8 / ClientProxy1_8 do.
 */
#include "fuzz_common.h"

#include "deskflow/KeyboardLayoutManager.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  deskflow::KeyboardLayoutManager manager({"en", "de", "fr"});
  manager.setRemoteLayouts(std::string_view(reinterpret_cast<const char *>(data), size));
  (void)manager.getRemoteLayouts().size();
  (void)manager.getMissedLayouts();
  return 0;
}

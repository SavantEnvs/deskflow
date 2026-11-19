/*
 * Clipboard wire format: the marshalled clipboard a peer sends at the end of a DCLP transfer
 * (format count, then per format: id, length, bytes). IClipboard::unmarshall (deskflow/IClipboard.cpp)
 * reads it into a Clipboard; the result is marshalled again and must read back unchanged.
 */
#include "fuzz_common.h"

#include "deskflow/Clipboard.h"

#include <cstdlib>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const std::string input(reinterpret_cast<const char *>(data), size);

  Clipboard clipboard;
  clipboard.unmarshall(input, 0);

  // what we accepted must survive a round trip
  const std::string again = clipboard.marshall();
  Clipboard copy;
  copy.unmarshall(again, 0);
  if (copy.marshall() != again)
    abort();

  if (clipboard.open(0)) {
    for (int f = 0; f < static_cast<int>(IClipboard::Format::TotalFormats); ++f) {
      const auto format = static_cast<IClipboard::Format>(f);
      if (clipboard.has(format))
        (void)clipboard.get(format).size();
    }
    clipboard.close();
  }
  return 0;
}

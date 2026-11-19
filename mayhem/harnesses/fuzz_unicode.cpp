/*
 * deskflow's hand-written text converters (base/Unicode.cpp), applied to clipboard text received
 * from the peer (UTF-8 on the wire, UCS-2/UTF-16 on the platform side). Every converter runs on the
 * input; text that decodes cleanly is converted back and must round-trip.
 */
#include "fuzz_common.h"

#include "base/Unicode.h"

#include <cstdlib>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const std::string input(reinterpret_cast<const char *>(data), size);

  const bool utf8 = Unicode::isUTF8(input);

  bool err = false;
  const std::string ucs2 = Unicode::UTF8ToUCS2(input, &err);
  err = false;
  const std::string utf16 = Unicode::UTF8ToUTF16(input, &err);
  if (utf8 && !err) {
    bool back = false;
    const std::string again = Unicode::UTF16ToUTF8(utf16, &back);
    // the converters drop a leading UTF-8 byte order mark
    const bool bom = input.size() >= 3 && input.compare(0, 3, "\xEF\xBB\xBF") == 0;
    if (!back && again != (bom ? input.substr(3) : input))
      abort();
  }

  err = false;
  (void)Unicode::UCS2ToUTF8(input, &err);
  err = false;
  (void)Unicode::UTF16ToUTF8(input, &err);
  (void)ucs2;
  return 0;
}

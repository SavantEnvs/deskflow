/*
 * Clipboard transfer reassembly: the bodies of the DCLP messages a peer sends (after the 4-byte code),
 * fed to ClipboardChunk::assemble (deskflow/ClipboardChunk.cpp) one message at a time, as
 * ServerProxy::setClipboard and ClientProxy1_6::recvClipboard do. Each body is
 * "%1i%4i%1i%s" (clipboard id, sequence, mark start/data/end, length-prefixed payload).
 * A finished transfer is unmarshalled into a Clipboard, like the proxies do.
 */
#include "fuzz_common.h"

#include "base/BaseException.h"
#include "deskflow/Clipboard.h"
#include "deskflow/ClipboardChunk.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  // the receive limit both proxies use by default (1 MB, Settings/Server m_maximumClipboardSize KiB)
  constexpr size_t kMaxClipboardBytes = 1024 * 1024;

  mayhem::FakeStream stream(std::string(reinterpret_cast<const char *>(data), size));
  std::string cached;
  ClipboardChunkAssemblyState state;

  try {
    for (int i = 0; i < 4096 && stream.isReady(); ++i) {
      ClipboardID id = 0;
      uint32_t seq = 0;
      const auto r = ClipboardChunk::assemble(&stream, cached, id, seq, state, kMaxClipboardBytes);
      if (r == TransferState::Finished) {
        Clipboard clipboard;
        clipboard.unmarshall(cached, 0);
        (void)clipboard.marshall();
      }
    }
  } catch (const BaseException &) {
    // a truncated message: the stream ran dry inside readf
  }
  return 0;
}

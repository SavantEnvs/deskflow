/*
 * Trusted TLS fingerprint database (trusted-servers / trusted-clients files):
 * FingerprintDatabase::readStream (net/FingerprintDatabase.cpp) parses "v2:<type>:<hex>" lines via
 * Fingerprint::fromDbLine; the result is written back with writeStream.
 */
#include "fuzz_common.h"

#include "net/FingerprintDatabase.h"

#include <QByteArray>
#include <QString>
#include <QTextStream>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
  mayhem::initOnce();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  QByteArray bytes(reinterpret_cast<const char *>(data), static_cast<qsizetype>(size));
  QTextStream in(&bytes, QIODevice::ReadOnly);
  FingerprintDatabase db;
  db.readStream(in);

  QString text;
  QTextStream out(&text, QIODevice::WriteOnly);
  db.writeStream(out);
  out.flush();
  return 0;
}

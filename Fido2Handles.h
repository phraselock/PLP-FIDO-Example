#pragma once

// RAII wrappers for libfido2 handles (their *_free functions take a pointer-to-pointer) and
// libfido2 error text. Used by the relying party and by LibFido2Client.
//
// libfido2 pulls in OpenSSL headers - include this before <windows.h> to avoid wincrypt macro clashes.

#include <fido.h>
#include <fido/es256.h>

#include <memory>
#include <string>

namespace Fido2
{
  struct DevDeleter { void operator()(fido_dev_t* d) const { fido_dev_close(d); fido_dev_free(&d); } };
  struct CredDeleter { void operator()(fido_cred_t* c) const { fido_cred_free(&c); } };
  struct AssertDeleter { void operator()(fido_assert_t* a) const { fido_assert_free(&a); } };
  struct InfoDeleter { void operator()(fido_cbor_info_t* i) const { fido_cbor_info_free(&i); } };
  struct Es256Deleter { void operator()(es256_pk_t* pk) const { es256_pk_free(&pk); } };

  using DevPtr = std::unique_ptr<fido_dev_t, DevDeleter>;
  using CredPtr = std::unique_ptr<fido_cred_t, CredDeleter>;
  using AssertPtr = std::unique_ptr<fido_assert_t, AssertDeleter>;
  using InfoPtr = std::unique_ptr<fido_cbor_info_t, InfoDeleter>;
  using Es256Ptr = std::unique_ptr<es256_pk_t, Es256Deleter>;

  // e.g. "FIDO_ERR_PIN_INVALID (49)"
  inline std::string ErrorText(int r)
  {
    return std::string(fido_strerr(r)) + " (" + std::to_string(r) + ")";
  }
}

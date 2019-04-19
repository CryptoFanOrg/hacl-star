#include <string>
#include <sstream>

#include "benchmark.h"

#ifdef HAVE_HACL
#include <Hacl_Ed25519.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#endif

class DSABenchmark: public Benchmark
{
  protected:
      size_t input_sz;

  public:
    static constexpr auto header = "Algorithm, Size [b], CPU Time (incl) [sec], CPU Time (excl) [sec], Avg Cycles/Op, Min Cycles/Op, Max Cycles/Op, Avg Cycles/Byte";

    DSABenchmark(size_t input_sz, const std::string & operation, std::string const & prefix) :
      Benchmark(prefix + " " + operation), input_sz(input_sz)
    {}

    virtual void bench_setup(const BenchmarkSettings & s) {}

    virtual void report(std::ostream & rs, const BenchmarkSettings & s)
    {
      rs << "\"" << name.c_str() << "\""
        << "," << input_sz
        << "," << toverall/(double)CLOCKS_PER_SEC
        << "," << ttotal/(double)CLOCKS_PER_SEC
        << "," << ctotal/(double)s.samples
        << "," << cmin
        << "," << cmax
        << "," << (ctotal/(double)input_sz)/(double)s.samples
        << "\n";
    }
};

class EverCryptEd25519: public DSABenchmark
{
  public:
  EverCryptEd25519(size_t input_sz) : DSABenchmark(input_sz, "sign", "EverCrypt") {}
  virtual void bench_func() {}
  virtual ~EverCryptEd25519() {}
};

#ifdef HAVE_OPENSSL
class OpenSSLEd25519Benchmark: public DSABenchmark
{
  protected:
    size_t skeylen;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *ours = NULL, *theirs = NULL, *shared = NULL;

  public:
    OpenSSLEd25519Benchmark(size_t input_sz) : DSABenchmark(input_sz, "sign", "OpenSSL") {}
    virtual void bench_setup(const BenchmarkSettings & s)
    {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      EVP_PKEY_keygen_init(ctx);
      EVP_PKEY_keygen(ctx, &ours);
      EVP_PKEY_CTX_free(ctx);

      EVP_PKEY_CTX *their_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      EVP_PKEY_keygen_init(their_ctx);
      EVP_PKEY_keygen(their_ctx, &theirs);
      EVP_PKEY_CTX_free(their_ctx);

      ctx = EVP_PKEY_CTX_new(ours, NULL);

      if (EVP_PKEY_derive_init(ctx) <= 0)
        throw std::logic_error("OpenSSL derive_init failed");
      if (EVP_PKEY_derive_set_peer(ctx, theirs) <= 0)
        throw std::logic_error("OpenSSL derive_set_peer failed");
    }
    virtual void bench_func()
    {
      //EVP_PKEY_derive(ctx, shared_secret, &skeylen)
    }
    virtual ~OpenSSLEd25519Benchmark() {  EVP_PKEY_CTX_free(ctx); }
};
#endif

void bench_ed25519(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192 };

  for (size_t ds: data_sizes)
  {
    std::stringstream filename;
    filename << "bench_ed25519_" << ds << ".csv";

    std::list<Benchmark*> todo = {
      new EverCryptEd25519(ds),

      #ifdef HAVE_OPENSSL
      new OpenSSLEd25519Benchmark(ds),
      #endif
      };

    Benchmark::run_batch(s, DSABenchmark::header, filename.str(), todo);
  }
}
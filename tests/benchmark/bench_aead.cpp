#include <stdexcept>
#include <sstream>
#include <iostream>
#include <fstream>

#include <time.h>
#include <benchmark.h>

extern "C" {
#include <EverCrypt_AEAD.h>
#ifdef HAVE_VALE
#include <EverCrypt_Vale.h>
#endif
}

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

class AEADBenchmark : public Benchmark
{
  protected:
    typedef __attribute__((aligned(32))) uint8_t aligned_uint8_t[32];
    size_t key_sz, msg_len, ad_len = 0;
    aligned_uint8_t *tag;
    aligned_uint8_t iv[16]; // 12 used
    aligned_uint8_t *key;
    aligned_uint8_t *plain;
    aligned_uint8_t *cipher;
    aligned_uint8_t *ad = 0;

  public:
    static constexpr auto header = "Algorithm, Size [b], CPU Time (incl) [sec], CPU Time (excl) [sec], Avg Cycles/Op, Min Cycles/Op, Max Cycles/Op, Avg Cycles/Byte";

    AEADBenchmark(size_t key_sz_bits, size_t tag_len, size_t msg_len, const std::string & prefix) : Benchmark(prefix)
    {
      if (key_sz_bits != 128 && key_sz_bits != 192 && key_sz_bits != 256)
        throw std::logic_error("Need key_sz in {128, 192, 256}");

      if (msg_len == 0)
        throw std::logic_error("Need msg_len > 0");

      this->key_sz = key_sz_bits/8;
      this->msg_len = msg_len;

      key = new aligned_uint8_t[key_sz];
      plain = new aligned_uint8_t[msg_len];
      cipher = new aligned_uint8_t[msg_len];
      tag = new aligned_uint8_t[tag_len];
    }

    virtual ~AEADBenchmark()
    {
      delete(tag);
      delete(cipher);
      delete(plain);
      delete(key);
    }

    virtual void bench_setup(const BenchmarkSettings & s)
    {
      randomize((char*)key, key_sz);
      randomize((char*)plain, msg_len);
    }

    virtual void report(std::ostream & rs, const BenchmarkSettings & s)
    {
      rs << "\"" << name.c_str() << "\""
        << "," << msg_len
        << "," << toverall/(double)CLOCKS_PER_SEC
        << "," << ttotal/(double)CLOCKS_PER_SEC
        << "," << ctotal/(double)s.samples
        << "," << cmin
        << "," << cmax
        << "," << (ctotal/(double)msg_len)/(double)s.samples
        << "\n";
    }
};

template<uint8_t type, size_t key_size_bits, size_t tag_len>
class EverCryptAEAD : public AEADBenchmark
{
  protected:
    EverCrypt_AEAD_state_s *state;

  public:
    EverCryptAEAD(size_t msg_len) :
      AEADBenchmark(key_size_bits, tag_len, msg_len, "EverCrypt")
      {
        switch (type) {
          case Spec_AEAD_AES128_GCM: set_name("EverCrypt\\nAES128\\nGCM"); break;
          case Spec_AEAD_AES256_GCM: set_name("EverCrypt\\nAES256\\nGCM"); break;
          case Spec_AEAD_CHACHA20_POLY1305: set_name("EverCrypt\\nCHACHA20\\nPOLY1305"); break;
          case Spec_AEAD_AES128_CCM: set_name("EverCrypt\\nAES128\\nCCM"); break;
          case Spec_AEAD_AES256_CCM: set_name("EverCrypt\\nAES256\\nCCM"); break;
          case Spec_AEAD_AES128_CCM8: set_name("EverCrypt\\nAES128\\nCCM8"); break;
          case Spec_AEAD_AES256_CCM8: set_name("EverCrypt\\nAES256\\nCCM8"); break;
          default: throw new std::logic_error("Unknown AEAD algorithm");
        }
      }
    virtual void bench_setup(const BenchmarkSettings & s)
    {
      if (EverCrypt_AEAD_create_in(type, &state, (uint8_t*)key) != EverCrypt_Error_Success)
        throw std::logic_error("AEAD context creation failed");
    }
    virtual void bench_func()
    {
      #ifdef _DEBUG
      if (
      #endif
        EverCrypt_AEAD_encrypt(state, (uint8_t*)iv, (uint8_t*)ad, ad_len, (uint8_t*)plain, msg_len, (uint8_t*)cipher, (uint8_t*)tag)
      #ifdef _DEBUG
        != EverCrypt_Error_Success) throw std::logic_error("AEAD encryption failed")
      #endif
      ;
    }
    virtual ~EverCryptAEAD()
      { EverCrypt_AEAD_free(state); }
};

#ifdef HAVE_VALE
template<size_t key_size_bits, size_t tag_len>
class Vale : public AEADBenchmark
{
  protected:
    gcm_args args;

  public:
    Vale(size_t msg_len) :
      AEADBenchmark(key_size_bits, tag_len, msg_len, "EverCrypt")
      {
        switch(key_size_bits) {
          case 128: set_name("Vale (old)\\nAES128\\nGCM"); break;
          case 256: set_name("Vale (old)\\nAES256\\nGCM"); break;
          default: throw new std::logic_error("Unknown algorithm");
        }
      }
    virtual void bench_setup(const BenchmarkSettings & s)
    {
      args.expanded_key = new uint8_t[15 * (128/8)];
      switch(key_size_bits) {
        case 128: old_aes128_key_expansion((uint8_t*)key, args.expanded_key);
        case 256: old_aes256_key_expansion((uint8_t*)key, args.expanded_key);
      }
    }
    virtual void bench_func()
    {
      args.plain = (uint8_t*)plain;
      args.plain_len = msg_len;
      args.aad = (uint8_t*)ad;
      args.aad_len = ad_len;
      args.iv = (uint8_t*)iv;
      args.cipher = (uint8_t*)cipher;
      args.tag = (uint8_t*)tag;
      switch(key_size_bits) {
      case 128: old_gcm128_encrypt(&args);
      case 256: old_gcm256_encrypt(&args);
      }
    }
    virtual ~Vale() { delete(args.expanded_key); }
};
#endif

#ifdef HAVE_OPENSSL
// See https://github.com/openssl/openssl/blob/master/demos/evp/aesgcm.c
#endif

int bench_aead(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::vector<std::string> data_filenames;
  std::vector<std::string> plot_specs_cycles;
  std::vector<std::string> plot_specs_bytes;

  for (size_t ds: data_sizes)
  {
    std::stringstream dsstr;
    dsstr << ds;

    std::stringstream data_filename;
    data_filename << "bench_aead_" << ds << ".csv";

    data_filenames.push_back(data_filename.str());
    if (plot_specs_cycles.empty())
    {
      plot_specs_cycles.push_back("using 5:xticlabels(1) title '" + dsstr.str() + " b'");
      plot_specs_bytes.push_back("using 8:xticlabels(1) title '" + dsstr.str() + " b'");
    }
    else
    {
      plot_specs_cycles.push_back("using 5 title '" + dsstr.str() + " b'");
      plot_specs_bytes.push_back("using 8 title '" + dsstr.str() + " b'");
    }

    std::list<Benchmark*> todo = {
      new EverCryptAEAD<Spec_AEAD_AES128_GCM, 128, 16>(ds),
      new EverCryptAEAD<Spec_AEAD_AES256_GCM, 256, 16>(ds),
      new EverCryptAEAD<Spec_AEAD_CHACHA20_POLY1305, 128, 16>(ds),
      // new EverCryptAEAD<Spec_AEAD_AES128_CCM, 128, 16>(ds), // unsupported?
      // new EverCryptAEAD<Spec_AEAD_AES256_CCM, 256, 16>(ds), // unsupported?
      // new EverCryptAEAD<Spec_AEAD_AES128_CCM8, 128, 8>(ds), // unsupported?
      // new EverCryptAEAD<Spec_AEAD_AES256_CCM8, 256, 8>(ds), // unsupported?

      #ifdef HAVE_VALE
      new Vale<128, 16>(ds),
      new Vale<256, 16>(ds),
      #endif

      #ifdef HAVE_OPENSSL
      #endif
      };

      Benchmark::run_batch(s, AEADBenchmark::header, data_filename.str(), todo);
  }

  std::stringstream extras;
  extras << "set boxwidth 0.8\n";
  extras << "set key top left inside\n";
  extras << "set style histogram clustered gap 3 title\n";
  extras << "set style data histograms\n";
  extras << "set bmargin 5\n";
  extras << "set xrange [0:]\n";

  Benchmark::make_plot(s,
                       "svg",
                       "AEAD Encryption Performance",
                       "",
                       "Avg. performance [CPU cycles/encryption]",
                       data_filenames,
                       "bench_aead_all_cycles.svg",
                       extras.str(),
                       plot_specs_cycles);

  Benchmark::make_plot(s,
                       "svg",
                       "AEAD Encryption Performance",
                       "",
                       "Avg. performance [CPU cycles/byte]",
                       data_filenames,
                       "bench_aead_all_bytes.svg",
                       extras.str(),
                       plot_specs_bytes);
}
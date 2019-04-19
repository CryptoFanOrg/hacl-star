#include <stdexcept>
#include <sstream>
#include <iostream>
#include <fstream>

#include <time.h>
#include <benchmark.h>

extern "C" {
#include <EverCrypt_AEAD.h>
}

class AEADBenchmark : public Benchmark
{
  protected:
    size_t key_sz, input_sz;
    unsigned char tag[16], iv[12];
    unsigned char *key;
    unsigned char *plain;
    unsigned char *cipher;

  public:
    static constexpr auto header = "Algorithm, Size [b], CPU Time (incl) [sec], CPU Time (excl) [sec], Avg Cycles/Hash, Min Cycles/Hash, Max Cycles/Hash, Avg Cycles/Byte";

    AEADBenchmark(size_t key_sz_bits, size_t input_sz, const std::string & prefix) : Benchmark(prefix)
    {
      if (key_sz_bits != 128 && key_sz_bits != 192 && key_sz_bits != 256)
        throw std::logic_error("Need key_sz in {128, 192, 256}");

      if (input_sz == 0)
        throw std::logic_error("Need input_sz > 0");

      this->key_sz = key_sz_bits/8;
      this->input_sz = input_sz;

      key = new unsigned char[key_sz];
      plain = new unsigned char[input_sz];
      cipher = new unsigned char[input_sz];
    }

    virtual ~AEADBenchmark()
    {
      delete(key);
      delete(plain);
      delete(cipher);
    }

    virtual void bench_setup(const BenchmarkSettings & s)
    {
      randomize((char*)key, key_sz);
      randomize((char*)plain, input_sz);
    }

    virtual void report(std::ostream & rs, const BenchmarkSettings & s)
    {
      rs << "\"" << name.c_str() << key_sz << "\""
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

template<int type, int key_sz_bits>
class EverCryptAEAD : public AEADBenchmark
{
  public:
    EverCryptAEAD(size_t input_sz) :
      AEADBenchmark(type /*EverCrypt_aead_keyLen(type)*/, input_sz, "EverCyrypt") {}
    virtual ~EverCryptAEAD() {}
    virtual void bench_func() {
      // EverCrypt_AEAD_state_s *s = EverCrypt_aead_create(type, key);
      // EverCrypt_aead_encrypt(s, iv, "", 0, plain, N, cipher, tag);
      // EverCrypt_aead_free(s);
    }
};

int bench_aead(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192 };

  for (size_t ds: data_sizes)
  {
    std::stringstream filename;
    filename << "bench_aead_" << ds << ".csv";

    std::list<Benchmark*> todo = {
      // EverCryptAEAD<EverCrypt_AES128_GCM, 128>(ds);
      // EverCryptAEAD<EverCrypt_AES256_GCM, 256>(ds);
      // EverCryptAEAD<EverCrypt_CHACHA20_POLY1305, 128>(ds);
      // EverCryptAEAD<EverCrypt_AES128_CCM, 128>(ds);
      // EverCryptAEAD<EverCrypt_AES256_CCM, 256>(ds);
      // EverCryptAEAD<EverCrypt_AES128_CCM8, 128>(ds);
      // EverCryptAEAD<EverCrypt_AES256_CCM8, 256>(ds);

      #ifdef HAVE_OPENSSL
      #endif
      };

    Benchmark::run_batch(s, AEADBenchmark::header, filename.str(), todo);
  }
}
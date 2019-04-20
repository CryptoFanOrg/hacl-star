#include <stdexcept>
#include <sstream>
#include <iostream>
#include <fstream>

#include <benchmark.h>

extern "C" {
#include <EverCrypt_Hash.h>
#ifdef HAVE_HACL
#include <Hacl_Hash.h>
#include <Hacl_SHA3.h>
#endif
}

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#include <openssl/md5.h>
#endif

class HashBenchmark : public Benchmark
{
  protected:
    uint8_t *src, *dst;
    size_t src_sz;

  public:
    static constexpr auto header = "Algorithm, Size [b], CPU Time (incl) [sec], CPU Time (excl) [sec], Avg Cycles/Hash, Min Cycles/Hash, Max Cycles/Hash, Avg Cycles/Byte";

    HashBenchmark(size_t src_sz, int type, int N, const std::string & prefix) : Benchmark(prefix), src(0), src_sz(src_sz)
    {
      if (src_sz == 0)
        throw std::logic_error("Need src_sz > 0");

      src = new uint8_t[src_sz];
      dst = new uint8_t[N/8];

      if (type >= 2)
      {
        std::stringstream ns;
        ns << prefix << " SHA" << type << "-" << N;
        set_name(ns.str());
      }
    }

    virtual ~HashBenchmark()
    {
      delete[](src);
      delete[](dst);
      src_sz = 0;
    }

    virtual void bench_setup(const BenchmarkSettings & s)
    {
      Benchmark::bench_setup(s);
      randomize((char*)src, src_sz);
    }

    virtual void report(std::ostream & rs, const BenchmarkSettings & s)
    {
      rs << "\"" << name.c_str() << "\""
        << "," << src_sz
        << "," << toverall/(double)CLOCKS_PER_SEC
        << "," << ttotal/(double)CLOCKS_PER_SEC
        << "," << ctotal/(double)s.samples
        << "," << cmin
        << "," << cmax
        << "," << (ctotal/(double)src_sz)/(double)s.samples
        << "\n";
    }
};

template<int type, int N>
class HaclHash : public HashBenchmark
{
  static void (*fun)(uint8_t *input, uint32_t input_len, uint8_t *dst);
  public:
    HaclHash(size_t src_sz) : HashBenchmark(src_sz, type, N, "HaCl") {}
    virtual ~HaclHash() {}
    virtual void bench_func() { fun(src, src_sz, dst); }
};

template<> void (*HaclHash<0, 128>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = Hacl_Hash_MD5_hash;
template<> void (*HaclHash<1, 160>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = Hacl_Hash_SHA1_hash;
template<> void (*HaclHash<2, 224>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = Hacl_Hash_SHA2_hash_224;
template<> void (*HaclHash<2, 256>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = Hacl_Hash_SHA2_hash_256;
template<> void (*HaclHash<2, 384>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = Hacl_Hash_SHA2_hash_384;
template<> void (*HaclHash<2, 512>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = Hacl_Hash_SHA2_hash_512;
typedef HaclHash<0, 128> HaclMD5;
typedef HaclHash<1, 160> HaclSHA1;

template<> void (*HaclHash<3, 224>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = [](uint8_t *input, uint32_t input_len, uint8_t *dst) { Hacl_SHA3_sha3_224(input_len, input, dst); };
template<> void (*HaclHash<3, 256>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = [](uint8_t *input, uint32_t input_len, uint8_t *dst) { Hacl_SHA3_sha3_256(input_len, input, dst); };
template<> void (*HaclHash<3, 384>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = [](uint8_t *input, uint32_t input_len, uint8_t *dst) { Hacl_SHA3_sha3_384(input_len, input, dst); };
template<> void (*HaclHash<3, 512>::fun)(uint8_t *input, uint32_t input_len, uint8_t *dst) = [](uint8_t *input, uint32_t input_len, uint8_t *dst) { Hacl_SHA3_sha3_512(input_len, input, dst); };

template<int type, int N>
class EverCryptHash : public HashBenchmark
{
  const static int id;
  public:
    EverCryptHash(size_t src_sz) : HashBenchmark(src_sz, type, N, "EverCrypt") {}
    virtual ~EverCryptHash() {}
    virtual void bench_func() { EverCrypt_Hash_hash(id, dst, src, src_sz); }
};

template<> const int EverCryptHash<0, 128>::id = Spec_Hash_Definitions_MD5;
template<> const int EverCryptHash<1, 160>::id = Spec_Hash_Definitions_SHA1;
template<> const int EverCryptHash<2, 224>::id = Spec_Hash_Definitions_SHA2_224;
template<> const int EverCryptHash<2, 256>::id = Spec_Hash_Definitions_SHA2_256;
template<> const int EverCryptHash<2, 384>::id = Spec_Hash_Definitions_SHA2_384;
template<> const int EverCryptHash<2, 512>::id = Spec_Hash_Definitions_SHA2_512;
typedef EverCryptHash<0, 128> EverCryptMD5;
typedef EverCryptHash<1, 160> EverCryptSHA1;

#ifdef HAVE_OPENSSL
template<int type, int N>
class OpenSSLHash : public HashBenchmark
{
  static unsigned char* (*fun)(const unsigned char *d, size_t n, unsigned char *md);

  public:
    OpenSSLHash(size_t src_sz) : HashBenchmark(src_sz, type, N, "OpenSSL") {}
    virtual ~OpenSSLHash() {}
    virtual void bench_func() { fun((unsigned char*)src, src_sz, (unsigned char*)dst); }
};

template<> unsigned char* (*OpenSSLHash<0, 128>::fun)(const unsigned char *d, size_t n, unsigned char *md) = MD5;
template<> unsigned char* (*OpenSSLHash<1, 160>::fun)(const unsigned char *d, size_t n, unsigned char *md) = SHA1;
template<> unsigned char* (*OpenSSLHash<2, 224>::fun)(const unsigned char *d, size_t n, unsigned char *md) = SHA224;
template<> unsigned char* (*OpenSSLHash<2, 256>::fun)(const unsigned char *d, size_t n, unsigned char *md) = SHA256;
template<> unsigned char* (*OpenSSLHash<2, 384>::fun)(const unsigned char *d, size_t n, unsigned char *md) = SHA384;
template<> unsigned char* (*OpenSSLHash<2, 512>::fun)(const unsigned char *d, size_t n, unsigned char *md) = SHA512;
typedef OpenSSLHash<0, 128> OpenSSLMD5;
typedef OpenSSLHash<1, 160> OpenSSLSHA1;
#endif

void bench_hash_plots(const BenchmarkSettings & s, const std::string & alg, const std::string & num_benchmarks, const std::string & data_filename)
{
  std::stringstream title;
  title << alg << " performance";

  std::stringstream plot_filename;
  plot_filename << "bench_hash_" << alg << ".svg";

  std::stringstream extras;
  extras << "set boxwidth 0.8\n";
  extras << "set key top left inside\n";
  extras << "set style histogram clustered gap 3 title\n";
  extras << "set style data histograms\n";
  extras << "set bmargin 5\n";

  Benchmark::plot_spec_t plot_specs_cycles = {
    #ifdef HAVE_HACL
    std::make_pair("< grep \"HaCl\" " + data_filename,  "using 5:xticlabels(2) title \"HaCl\""),
    std::make_pair("", "using 0:5:xticlabels(2):(sprintf(\"%0.0f\", $5)) with labels font \"Courier,8\" offset char -1.25,1 rotate by 90 notitle"),
    #endif
    std::make_pair("< grep \"EverCrypt\" " + data_filename, "using 5 title \"EverCrypt\""),
    std::make_pair("", "using 0:5:xticlabels(2):(sprintf(\"%0.0f\", $5)) with labels font \"Courier,8\" offset char +0.00,1 rotate by 90 notitle"),
    #ifdef HAVE_OPENSSL
    std::make_pair("< grep \"OpenSSL\" " + data_filename, "using 5 title \"OpenSSL\""),
    std::make_pair("", "using 0:5:xticlabels(2):(sprintf(\"%0.0f\", $5)) with labels font \"Courier,8\" offset char +1.25,1 rotate by 90 notitle")
    #endif
   };

  Benchmark::plot_spec_t plot_specs_cycles_candlesticks = {
    #ifdef HAVE_HACL
    std::make_pair("< grep \"HaCl\" " + data_filename, "using 0:5:6:7:5:xticlabels(2) title \"HaCl\" with candlesticks whiskerbars .25"),
    #endif
    std::make_pair("< grep \"EverCrypt\" " + data_filename, "using 0:5:6:7:5:xticlabels(2) title \"EverCrypt\" with candlesticks whiskerbars .25"),
    #ifdef HAVE_OPENSSL
    std::make_pair("< grep \"OpenSSL\" " + data_filename, "using 0:5:6:7:5:xticlabels(2) title \"OpenSSL\" with candlesticks whiskerbars .25")
    #endif
   };

  Benchmark::plot_spec_t plot_specs_bytes = {
    #ifdef HAVE_HACL
    std::make_pair("< grep \"HaCl\" " + data_filename, "using 8:xticlabels(2) title \"HaCl\""),
    std::make_pair("", "using 0:8:xticlabels(2):(sprintf(\"%0.0f\", $5)) with labels font \"Courier,8\" offset char -1.25,1 rotate by 90 notitle"),
    #endif
    std::make_pair("< grep \"EverCrypt\" " + data_filename, "using 8 title \"EverCrypt\""),
    std::make_pair("", "using 0:8:xticlabels(2):(sprintf(\"%0.0f\", $5)) with labels font \"Courier,8\" offset char +0.00,1 rotate by 90 notitle"),
    #ifdef HAVE_OPENSSL
    std::make_pair("< grep \"OpenSSL\" " + data_filename, "using 8 title \"OpenSSL\""),
    std::make_pair("", "using 0:8:xticlabels(2):(sprintf(\"%0.0f\", $5)) with labels font \"Courier,8\" offset char +1.25,1 rotate by 90 notitle")
    #endif
   };

  Benchmark::make_plot(s,
                       "svg",
                       title.str(),
                       "Message length [bytes]",
                       "Avg. performance [CPU cycles/hash]",
                       plot_specs_cycles,
                       plot_filename.str(),
                       extras.str(),
                       true);

  plot_filename.str("");
  plot_filename << "bench_hash_" << alg << "_candlesticks.svg";

  Benchmark::make_plot(s,
                       "svg",
                       title.str(),
                       "Message length [bytes]",
                       "Avg. performance [CPU cycles/hash]",
                       plot_specs_cycles_candlesticks,
                       plot_filename.str(),
                       extras.str(),
                       true);

  plot_filename.str("");
  plot_filename << "bench_hash_" << alg << "_bytes.svg";

  Benchmark::make_plot(s,
                       "svg",
                       title.str(),
                       "Message length [bytes]",
                       "Avg. performance [CPU cycles/hash]",
                       plot_specs_bytes,
                       plot_filename.str(),
                       extras.str(),
                       true);
}

void bench_hash_alg(const BenchmarkSettings & s, const std::string & alg, std::list<Benchmark*> & todo)
{
  std::stringstream data_filename;
  data_filename << "bench_hash_" << alg << ".csv";

  std::stringstream num_benchmarks;
  num_benchmarks << todo.size();

  Benchmark::run_batch(s, HashBenchmark::header, data_filename.str(), todo);

  bench_hash_plots(s, alg, num_benchmarks.str(), data_filename.str());
}

void bench_md5(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
     todo.push_back(new EverCryptMD5(ds));
     #ifdef HAVE_HACL
     todo.push_back(new HaclMD5(ds));
     #endif
     #ifdef HAVE_OPENSSL
     todo.push_back(new OpenSSLMD5(ds));
     #endif
  }

  bench_hash_alg(s, "MD5", todo);
}

void bench_sha1(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
     todo.push_back(new EverCryptSHA1(ds));
     #ifdef HAVE_HACL
     todo.push_back(new HaclSHA1(ds));
     #endif
     #ifdef HAVE_OPENSSL
     todo.push_back(new OpenSSLSHA1(ds));
     #endif
  }

  bench_hash_alg(s, "SHA1", todo);
}

void bench_sha2_224(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    todo.push_back(new EverCryptHash<2, 224>(ds));
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<2, 224>(ds));
    #endif
    #ifdef HAVE_OPENSSL
    todo.push_back(new OpenSSLHash<2, 224>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA2_224", todo);
}

void bench_sha2_256(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    todo.push_back(new EverCryptHash<2, 256>(ds));
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<2, 256>(ds));
    #endif
    #ifdef HAVE_OPENSSL
    todo.push_back(new OpenSSLHash<2, 256>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA2_256", todo);
}

void bench_sha2_384(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    todo.push_back(new EverCryptHash<2, 384>(ds));
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<2, 384>(ds));
    #endif
    #ifdef HAVE_OPENSSL
    todo.push_back(new OpenSSLHash<2, 384>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA2_384", todo);
}

void bench_sha2_512(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    todo.push_back(new EverCryptHash<2, 512>(ds));
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<2, 512>(ds));
    #endif
    #ifdef HAVE_OPENSSL
    todo.push_back(new OpenSSLHash<2, 512>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA2_512", todo);
}

void bench_sha2(const BenchmarkSettings & s)
{
  bench_sha2_224(s);
  bench_sha2_256(s);
  bench_sha2_384(s);
  bench_sha2_512(s);
}

void bench_sha3_224(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<3, 224>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA3_224", todo);
}

void bench_sha3_256(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<3, 256>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA3_256", todo);
}

void bench_sha3_384(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<3, 384>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA3_384", todo);
}

void bench_sha3_512(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  std::list<Benchmark*> todo;

  for (size_t ds: data_sizes)
  {
    #ifdef HAVE_HACL
    todo.push_back(new HaclHash<3, 512>(ds));
    #endif
  }

  bench_hash_alg(s, "SHA3-512", todo);
}

void bench_sha3(const BenchmarkSettings & s)
{
  bench_sha3_224(s);
  bench_sha3_256(s);
  bench_sha3_384(s);
  bench_sha3_512(s);
}

void bench_hash(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

  bench_md5(s);
  bench_sha1(s);
  bench_sha2(s);

  Benchmark::plot_spec_t plot_specs_cycles = {
    std::make_pair("bench_hash_MD5.csv",      "using 5:xticlabels(1) title \"MD5\""),
    std::make_pair("bench_hash_SHA1.csv",     "using 5 title \"SHA1\""),
    std::make_pair("bench_hash_SHA2_224.csv", "using 5 title \"SHA2-224\""),
    std::make_pair("bench_hash_SHA2_256.csv", "using 5 title \"SHA2-256\""),
    std::make_pair("bench_hash_SHA2_384.csv", "using 5 title \"SHA2-384\""),
    std::make_pair("bench_hash_SHA2_512.csv", "using 5 title \"SHA2-512\"")
  };

  Benchmark::plot_spec_t plot_specs_bytes = {
    std::make_pair("bench_hash_MD5.csv",      "using 8:xticlabels(1) title \"MD5\""),
    std::make_pair("bench_hash_SHA1.csv",     "using 8 title \"SHA1\""),
    std::make_pair("bench_hash_SHA2_224.csv", "using 8 title \"SHA2-224\""),
    std::make_pair("bench_hash_SHA2_256.csv", "using 8 title \"SHA2-256\""),
    std::make_pair("bench_hash_SHA2_384.csv", "using 8 title \"SHA2-384\""),
    std::make_pair("bench_hash_SHA2_512.csv", "using 8 title \"SHA2-512\"")
  };

  int i = 0;
  for (size_t ds : data_sizes)
  {
    std::stringstream title;
    title << "Hash performance (message length " << ds << " bytes)";

    std::stringstream plot_filename;
    plot_filename << "bench_hash_all_" << ds << "_cycles.svg";

    std::stringstream extras;
    extras << "set xtics norotate\n";
    extras << "set key on\n";
    extras << "set style histogram clustered gap 3 title\n";
    extras << "set style data histograms\n";
    extras << "set xrange [" << i << ".5:" << i+3 << ".5]";

    Benchmark::make_plot(s,
                         "svg",
                         title.str(),
                         "",
                         "Avg. performance [CPU cycles/hash]",
                         plot_specs_cycles,
                         plot_filename.str(),
                         extras.str());

    plot_filename.str("");
    plot_filename << "bench_hash_all_" << ds << "_bytes.svg";

    Benchmark::make_plot(s,
                         "svg",
                         title.str(),
                         "",
                         "Avg. performance [CPU cycles/byte]",
                         plot_specs_bytes,
                         plot_filename.str(),
                         extras.str());

    i++;
    #ifdef HAVE_HACL
    i++;
    #endif
    #ifdef HAVE_OPENSSL
    i++;
    #endif
  }
}
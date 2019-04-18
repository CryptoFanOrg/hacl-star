#include <string>
#include <sstream>

#include "benchmark.h"

class Curve25519Benchmark: public Benchmark
{
  protected:
      size_t input_sz;

  public:
    static constexpr auto header = "Algorithm, Size [b], CPU Time (incl) [sec], CPU Time (excl) [sec], Avg Cycles/Op, Min Cycles/Op, Max Cycles/Op, Avg Cycles/Byte";

    Curve25519Benchmark(size_t input_sz, std::string const & prefix) : Benchmark(prefix), input_sz(input_sz) {}

    virtual void bench_setup(const BenchmarkSettings & s) {}

    virtual void report(std::ostream & rs, const BenchmarkSettings & s)
    {
      rs << "\"" << name.c_str() << "\""
        << "," << input_sz
        << "," << toverall/(double)CLOCKS_PER_SEC
        << "," << ttotal/(double)CLOCKS_PER_SEC
        << "," << ctotal/(double)s.samples
        << "," << cmin << cmax
        << "," << (ctotal/(double)input_sz)/(double)s.samples
        << "\n";
    }
};

class EverCryptCurve25519: public Curve25519Benchmark
{
  public:
  EverCryptCurve25519(size_t input_sz) : Curve25519Benchmark(input_sz, "EverCrypt") {}
  virtual ~EverCryptCurve25519() {}
  virtual void bench_func() {}
};

class RFC7748Benchmark: public Curve25519Benchmark
{
  public:
    RFC7748Benchmark(size_t input_sz) : Curve25519Benchmark(input_sz, "RFC 7748") {}
    virtual ~RFC7748Benchmark() {}
    virtual void bench_func() {}
};

void bench_curve25519(const BenchmarkSettings & s)
{
  size_t data_sizes[] = { 1024, 2048, 4096, 8192 };

  for (size_t ds: data_sizes)
  {
    std::stringstream filename;
    filename << "bench_curve25519_" << ds << ".csv";

    std::set<Benchmark*> todo = {
      new EverCryptCurve25519(ds),

      #ifdef HAVE_OPENSSL
      #endif
      };

    Benchmark::run_all(s, Curve25519Benchmark::header, filename.str(), todo);
  }
}
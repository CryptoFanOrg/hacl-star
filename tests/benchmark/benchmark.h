
#ifndef _HACL_PERFTEST_H_
#define _HACL_PERFTEST_H_

#include <cstddef>
#include <cstdint>
#include <ctime>

#include <string>
#include <iostream>
#include <list>
#include <vector>

#define ABORT_BENCHMARK(msg, rv) { printf("\nABORT: %s\n", msg); return rv; }

typedef uint64_t cycles;

class BenchmarkSettings
{
  public:
    unsigned int seed = 0;
    size_t samples = 10000;
    std::list<std::string> families_to_run;
};

class Benchmark
{
  protected:
    cycles cbegin, cend, cdiff, ctotal = 0, cmax = 0, cmin = -1;
    size_t tbegin, tend, tdiff, ttotal = 0;
    size_t toverall;

    std::string name;

    static void escape(char c, std::string & str);
    static std::string escape(const std::string & str);

  public:
    Benchmark();
    Benchmark(const std::string & name);
    virtual ~Benchmark() {}

    virtual void pre(const BenchmarkSettings & s) { srand(s.seed); toverall = clock();}
    virtual void run(const BenchmarkSettings & s);
    virtual void bench_setup(const BenchmarkSettings & s) {};
    virtual void bench_func() = 0;
    virtual void bench_cleanup(const BenchmarkSettings & s) {};
    virtual void post(const BenchmarkSettings & s) { toverall = clock() - toverall; }
    virtual void report(std::ostream & rs, const BenchmarkSettings & s) = 0;

    void set_name(const std::string & name);
    std::string get_name() const { return name; }


    // Global tools, just in here for the namespace

    static std::string get_runtime_config();
    static void set_runtime_config(int shaext, int aesni, int pclmulqdq, int avx, int avx2, int bmi2, int adx, int hacl, int vale);
    static std::pair<std::string, std::string> & get_build_config(bool escaped=false);

    static void initialize();
    static void randomize(char *buf, size_t buf_sz);
    static inline void randomize(unsigned char *buf, size_t buf_sz)
    {
      randomize((char*)buf, buf_sz);
    }

    static __inline__ cycles cpucycles_begin(void)
    {
      uint64_t rax,rdx,aux;
      asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
      return (rdx << 32) + rax;
    }

    static __inline__ cycles cpucycles_end(void)
    {
      uint64_t rax,rdx,aux;
      asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
      return (rdx << 32) + rax;
    }

    static void run_batch(const BenchmarkSettings & s,
                          const std::string & data_header,
                          const std::string & data_filename,
                          std::list<Benchmark*> & benchmarks);

    typedef std::vector<std::pair<std::string, std::string> > plot_spec_t;

    static void make_plot(const BenchmarkSettings & s,
                          const std::string & terminal,
                          const std::string & title,
                          const std::string & xtitle,
                          const std::string & ytitle,
                          const plot_spec_t & plot_specs,
                          const std::string & plot_filename,
                          const std::string & plot_extras,
                          bool add_key = false);
};

#endif
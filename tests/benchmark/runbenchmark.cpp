#include <cstdlib>
#include <string>
#include <cstring>
#include <set>

#include "benchmark.h"

#include "bench_hash.h"
#include "bench_aead.h"


BenchmarkSettings & parse_args(int argc, char const ** argv)
{
  static BenchmarkSettings r;

  for (int i = 1; i < argc; i++)
  {
    if (*argv[i] == '-')
    {
      /* option */
      if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0 ||
          strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "/?") == 0)
      {
        std::cout << "Usage: " << argv[0] << " [-h] [--help] [-s seed] [-n samples] families ...\n";
        exit(1);
      }
      else if (strcmp(argv[i], "-s") == 0)
        r.seed = strtoul(argv[++i], NULL, 10);
      else if (strcmp(argv[i], "-n") == 0)
        r.samples = strtoul(argv[++i], NULL, 10);
    }
    else
      r.families_to_run.insert(argv[i]);
  }

  if (r.families_to_run.empty())
  {
    // Add default set of benchmarks
    r.families_to_run.insert("hash_all");
    r.families_to_run.insert("aead");
    r.families_to_run.insert("curve25519");
  }

  if (r.families_to_run.find("hash_all") != r.families_to_run.end())
  {
    r.families_to_run.erase("hash_md5");
    r.families_to_run.erase("hash_sha1");
    r.families_to_run.erase("hash_sha2");
    r.families_to_run.erase("hash_sha2_224");
    r.families_to_run.erase("hash_sha2_256");
    r.families_to_run.erase("hash_sha2_384");
    r.families_to_run.erase("hash_sha2_512");
  }

  if (r.families_to_run.find("hash_sha2") != r.families_to_run.end())
  {
    r.families_to_run.erase("hash_sha2_224");
    r.families_to_run.erase("hash_sha2_256");
    r.families_to_run.erase("hash_sha2_384");
    r.families_to_run.erase("hash_sha2_512");
  }

  return r;
}

#define BENCH(X) if (b == #X) bench_##X(s)

int main(int argc, char const **argv)
{
  Benchmark::initialize();

  BenchmarkSettings & s = parse_args(argc, argv);

  Benchmark::set_runtime_config(1, 1, 1, 1, 1, 1, 1, 1, 1);

  while (!s.families_to_run.empty())
  {
    auto fst = s.families_to_run.begin();
    std::string b = *fst;
    s.families_to_run.erase(fst);

    BENCH(hash_md5);
    BENCH(hash_sha1);
    BENCH(hash_sha2_224);
    BENCH(hash_sha2_256);
    BENCH(hash_sha2_384);
    BENCH(hash_sha2_512);
    BENCH(hash_all);
  }

  return 0;
}
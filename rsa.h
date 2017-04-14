#include <iostream>
#include <ctime>
#include <random>
#include <cmath>
#include <gmpxx.h>
#include <utility>
#include <sstream>
#include <time.h>
#include <stdlib.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <thread>
#include <future>

class RSA_Engine {
private:
  static mpz_class gcd(mpz_class a, mpz_class b);
  static bool prime_check(mpz_class p);

public:
  RSA_Engine();

  static mpz_class generatePrime(const unsigned int keySize = 1024);
  std::pair<std::pair<mpz_class, mpz_class>, std::pair<mpz_class, mpz_class>> generateKeyPair(const unsigned int keysz);
  mpz_class encryptByte(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, const unsigned int n);
  mpz_class decryptByte(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, mpz_class enc);

  std::vector<mpz_class> encryptString(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, std::string data);
  std::string decryptString(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, std::vector<mpz_class> encryptedString);
};

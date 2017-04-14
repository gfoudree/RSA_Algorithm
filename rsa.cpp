
#include "rsa.h"
using namespace std;

RSA_Engine::RSA_Engine() {}

mpz_class RSA_Engine::generatePrime(const unsigned int keySize)
{
  unsigned int randNum[128] = {0}; //Unsigned int = 4 bytes / 32 bits
  syscall(SYS_getrandom, (void*)randNum, (keySize/8)/2, 0); //1024 bits to bytes. Our function takes bytes. Getting 128 random bytes

  std::string randStr;
  for (auto a : randNum)
  {
    if (a != 0) {
      randStr += std::to_string(a);
    }
  }
  mpz_class mpzRand;
  mpz_init_set_str(mpzRand.get_mpz_t(), randStr.c_str(), 10);
  mpz_setbit(mpzRand.get_mpz_t(), mp_bitcnt_t(keySize/2)-1); //Set top 2 bits, and last bit
  mpz_setbit(mpzRand.get_mpz_t(), mp_bitcnt_t((keySize/2)-2));
  mpz_setbit(mpzRand.get_mpz_t(), mp_bitcnt_t(0));
  while (mpz_probab_prime_p(mpzRand.get_mpz_t(), 15) != 1) { mpzRand += 2; }
  return mpzRand;
}

mpz_class mul_inv(mpz_class a, mpz_class b)
{
	mpz_class b0 = b, t, q;
	mpz_class x0 = 0, x1 = 1;
	if (b == 1) return 1;
	while (a > 1) {
		q = a / b;
		t = b, b = a % b, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}

std::pair<std::pair<mpz_class, mpz_class>, std::pair<mpz_class, mpz_class>> RSA_Engine::generateKeyPair(const unsigned int keysz)
{
  mpz_class pub, priv;
  std::pair<mpz_class, mpz_class> pubKey, privKey;

  random_device rd;
  mt19937 mt(rd());
  uniform_int_distribution<int> udist(keysz/2, keysz);

  const unsigned int primeSz = keysz;
  mpz_class p, q;
  auto future1 = std::async(generatePrime, primeSz);
  auto future2 = std::async(generatePrime, primeSz);

  p = future1.get();
  q = future2.get();

  cout << "Got muh primez!" << endl;
  const mpz_class n = p * q;
  const mpz_class totient = (p-1)*(q-1);
  mpz_class e = 65537, d = 1;

  while (gcd(e, totient) != 1) { e = udist(mt); }
  d = mul_inv(e, totient);
  while (((d*e) % totient) != 1) { d++; }

  pubKey = std::make_pair(mpz_class(e), mpz_class(n));
  privKey = std::make_pair(mpz_class(d), mpz_class(n));
  //Public key is (e, n), Private key is (d, n)

  std::cout << "Generated RSA Parameters:\np = " << p << "\nq = " << q << "\nn = " << n << "\nTotient = " << totient << "\nd = " << d << "\ne = " << e << endl << endl;
  std::cout << "Public Key: (" << e << "," << n << ")\nPrivate Key: (" << d << "," << n << ")\n\n";
  return std::make_pair(pubKey, privKey);
}

mpz_class RSA_Engine::gcd(mpz_class a, mpz_class b)
{
  if (a == 0)
    return b;
  if (b == 0)
    return a;

  return gcd(b, (a % b));
}

bool RSA_Engine::prime_check(mpz_class num)
{
  if (num <= 3) {
        return num > 1;
    } else if (num % 2 == 0 || num % 3 == 0) {
        return false;
    } else {
        for (int i = 5; i * i <= num; i += 6) {
            if (num % i == 0 || num % (i + 2) == 0) {
                return false;
            }
        }
        return true;
    }
}

mpz_class RSA_Engine::encryptByte(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, const unsigned int n)
{
  mpz_class encrypted, toEncrypt;
  toEncrypt = n;
  mpz_powm(encrypted.get_mpz_t(), toEncrypt.get_mpz_t(), get<0>(publicKey).get_mpz_t(), get<1>(publicKey).get_mpz_t());
  return encrypted;
}

mpz_class RSA_Engine::decryptByte(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, mpz_class enc)
{
  mpz_class decrypted;
  mpz_powm(decrypted.get_mpz_t(), enc.get_mpz_t(), get<0>(privateKey).get_mpz_t(), get<1>(privateKey).get_mpz_t());
  return decrypted;
}

std::vector<mpz_class> RSA_Engine::encryptString(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, std::string data)
{
  std::vector<mpz_class> encryptedData;
  for (auto a : data)
  {
    encryptedData.push_back(encryptByte(publicKey, privateKey, a));
  }
  return encryptedData;
}

std::string RSA_Engine::decryptString(std::pair<mpz_class, mpz_class> publicKey, std::pair<mpz_class, mpz_class> privateKey, std::vector<mpz_class> encryptedString)
{
  std::ostringstream decryptedData;
  for (auto a : encryptedString)
  {
    decryptedData << (char)mpz_get_ui(decryptByte(publicKey, privateKey, a).get_mpz_t());
  }
  return decryptedData.str();
}

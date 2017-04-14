#include "rsa.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
      std::cout << "Please specify a string to encrypt and a keylength!\n\t./rsa keylength Encrypt_Me!\nEg: ./rsa 1024 Encrypt_Me!\n";
      return -1;
    }
    RSA_Engine re;
    std::pair<std::pair<mpz_class, mpz_class>, std::pair<mpz_class, mpz_class>> keyPair = re.generateKeyPair(atoi(argv[1]));

    std::vector<mpz_class> encStr = re.encryptString(std::get<0>(keyPair), std::get<1>(keyPair), argv[2]);
    std::string decryptedString = re.decryptString(std::get<0>(keyPair), std::get<1>(keyPair), encStr);
    std::string encryptedString;

    for (auto a : encStr)
    {
      std::ostringstream ss;
      ss << a;
      encryptedString += ss.str();
    }

    std::cout << std::endl << "---------------------------\nEncrypting: \"" << argv[2] << "\"\nEncrypted = " << encryptedString << "\nDecrypted = " << decryptedString << std::endl;
    return 0;
}

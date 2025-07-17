#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <cryptopp/osrng.h>  // for AutoSeededRandomPool
#include <cryptopp/secblock.h> // for SecByteBlock
#include <fstream>
#include <cstdlib>
#include <thread>
#include <chrono>

using namespace CryptoPP;

bool CheckForKey();
bool login();
void startup();
bool CreateAccount();
std::string Encrypt(std::string UnencryptedText);
std::string Decrypt(const std::string& EncryptedText);
std::string GenerateSalt(size_t length = 16);
bool LoadPasswords();

std::vector<std::string> DecryptedSavedPasswords;
std::vector<std::string> Websites;

std::vector<std::string> SecurityQuestions = {"What was your first pet's name: ", "Who was your first kiss: ", "What is your mothers maiden name: "};

std::string Password;
std::string name;

int Choice;
int DummyInt;

bool startupcomplete = false;


byte key[AES::DEFAULT_KEYLENGTH] = {};
byte iv[AES::BLOCKSIZE] = {};

int main() {
    std::system("clear");
    if (!startupcomplete)
        startup();

    while (true) {
        std::cout << "New Password (1)" << std::endl;
        std::cout << "Read Passwords (2)" << std::endl;
        std::cout << "Exit (3)" << std::endl;

        std::cout << "Choice: ";
        std::cin >> Choice;

        switch (Choice) {
            case 1: {
                std::string Password;
                std::string Website;
                std::cout << "Website: ";
                std::cin >> Website;
                std::cout << "Password: ";
                std::cin >> Password;

                try {
                    std::string EncryptedPassword = Encrypt(Password);
                    std::string Full = Website + ":" + EncryptedPassword;
                    std::ofstream PasswordFile("passwords.key", std::ios::app);
                    if (PasswordFile.is_open()) {
                        PasswordFile << std::endl << Full;
                    }
                    std::cout << "Password saved successfully" << std::endl;
                    std::cout << "Please restart the program for it to be shown in the manager" << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << e.what() << '\n';
                }
                break;
            }
            case 2: {
                std::system("clear");
                for (size_t i = 0; i < DecryptedSavedPasswords.size(); i++) {
                    std::cout << Websites[i] << ": " << DecryptedSavedPasswords[i] << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::seconds(5));

                break;
            }
            case 3: {
                exit(0);
            }
            default: {
                std::cout << "Invalid choice. Try again." << std::endl;
            }
        }
    }
}

bool CheckForKey()
{
    std::ifstream four("IV.key");
    std::ifstream KeyFile("key.key");
    if (four.is_open() && KeyFile.is_open())
    {
        std::ifstream PersonalInfo("information.txt");
        if (PersonalInfo.is_open())
        {
            std::getline(PersonalInfo, name);
        }
        return true;
    }
    else
    {
        if (four.is_open())
        {
            std::cout << "unable to find key file"<<std::endl;
            std::cout << "Attempting to generate key file" << std::endl;
            try
            {
                AutoSeededRandomPool prng;
                prng.GenerateBlock(key, sizeof(key));
                std::ofstream WriteKeyFile("key.key");
                if (WriteKeyFile.is_open())
                {
                    WriteKeyFile << key;
                }
            }
            catch (...)
            {
                std::cout << "Failed to generate key file" << std::endl;
                return false;
            }

        }
        else if (KeyFile.is_open())
        {
            AutoSeededRandomPool prng;
            prng.GenerateBlock(iv, sizeof(iv));
            std::ofstream WriteivFile("iv.key");
            if (WriteivFile.is_open())
            {
                WriteivFile << iv;
            }
            WriteivFile.close();
        }
        else
        {
            std::cout << "Welcome to keycrypt" << std::endl;
            std::cout << "Enter your name: ";
            std::cin >> name;
            std::cout << "Welcome " << name << std::endl;
            std::cout << "Generating encryption keys" << std::endl;
            CreateAccount();
            std::ofstream PersonalInfo("information.txt");
            if (PersonalInfo.is_open())
            {
                PersonalInfo << name;
            }
            try
            {
                PersonalInfo.close();
                AutoSeededRandomPool prng;
                prng.GenerateBlock(iv, sizeof(iv));
                std::ofstream WriteivFile("iv.key");
                if (WriteivFile.is_open())
                {
                    WriteivFile << iv;
                }
                prng.GenerateBlock(key, sizeof(key));
                std::ofstream WriteKeyFile("key.key");
                if (WriteKeyFile.is_open())
                {
                    WriteKeyFile << key;
                }
                WriteKeyFile.close();
                WriteivFile.close();
            }
            catch (...)
            {
                return false;
            }
        }
        return true;
    }

}

void startup()
{
    std::cout << "Running startup"<<std::endl;
    if (CheckForKey())
    {
        std::cout << "Found keys!"<<std::endl;
    }
    else
    {
        std::cout << "something went wrong please restart the program" << std::endl;
    }
    if (login())
    {

    }
    else
    {
        exit(0);
    }
    //generate keys and collect user's name

    if (LoadPasswords())
    {
        std::cout << "Passwords loaded successfully" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        std::system("clear");
    }
    startupcomplete = true;
}


bool login()
{
    std::ifstream File("account.key");

    if (!File.is_open()) {
        std::cerr << "Failed to open account.key file." << std::endl;
        return false;
    }

    std::string salt;
    std::string userEnc, passEnc, WhichSecurityQuestion, SecQuestionAnsEnc;

    // Read salt and encrypted lines
    std::getline(File, salt);                  // Line 1: salt (hex string)
    std::getline(File, userEnc);               // Line 2: encrypted (salt + username)
    std::getline(File, passEnc);               // Line 3: encrypted (salt + password)
    std::getline(File, WhichSecurityQuestion); // Line 4: integer as string (security question index)
    std::getline(File, SecQuestionAnsEnc);     // Line 5: encrypted (salt + security answer)

    File.close();

    // Decrypt the encrypted strings
    std::string DecryptedUser = Decrypt(userEnc);
    std::string DecryptedPass = Decrypt(passEnc);
    std::string DecryptedSecAns = Decrypt(SecQuestionAnsEnc);

    // Remove salt prefix from decrypted strings
    if (DecryptedUser.size() < salt.size() ||
        DecryptedPass.size() < salt.size() ||
        DecryptedSecAns.size() < salt.size())
    {
        std::cerr << "Decrypted data is corrupted or salt mismatch." << std::endl;
        return false;
    }

    DecryptedUser = DecryptedUser.substr(salt.size());
    DecryptedPass = DecryptedPass.substr(salt.size());
    DecryptedSecAns = DecryptedSecAns.substr(salt.size());

    int stoiWSQ = std::stoi(WhichSecurityQuestion);

    int attempts = 0;
    const int maxAttempts = 3;
    std::string AttemptedUsername;
    std::string AttemptedPassword;
    std::string SecQuestionAnsField;

    std::cout << "Welcome back " << name << std::endl;

    while (attempts < maxAttempts)
    {
        std::cout << "Username: ";
        std::cin >> AttemptedUsername;
        std::cout << "Password: ";
        std::cin >> AttemptedPassword;

        if (AttemptedUsername == DecryptedUser && AttemptedPassword == DecryptedPass)
        {
            return true;
        }

        attempts++;
        std::cout << "Incorrect username or password. Attempts remaining: " << (maxAttempts - attempts) << std::endl;
    }

    // After max attempts, ask security question
    std::cout << "Your security question is: " << SecurityQuestions[stoiWSQ - 1] << std::endl;
    std::cout << "Answer: ";
    std::cin >> SecQuestionAnsField;

    if (SecQuestionAnsField == DecryptedSecAns)
    {
        std::cout << "Correct!"<<std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return true;
    }
    else
    {
        std::cout << "Incorrect answer to security question." << std::endl;
        return false;
    }
}


bool CreateAccount() {
    std::string UserPassword, ConfirmUserPassword, Username;

    std::cout << "Username: ";
    std::cin >> Username;

    std::cout << "Password: ";
    std::cin >> UserPassword;

    std::cout << "Confirm password: ";
    std::cin >> ConfirmUserPassword;

    if (ConfirmUserPassword != UserPassword) {
        std::cout << "Passwords did not match. Try again!" << std::endl;
        return CreateAccount();  // FIXED: use return here
    }


    int SecurityQuestionCheck;
    std::string SecurityQuestion;
    //clear the screen but thats pretty fucking obvious 
    std::system("clear");
    std::cout << "Security Question"<<std::endl;
    std::cout << "(1) First pet name"<<std::endl;
    std::cout << "(2) First Kiss"<<std::endl;
    std::cout << "(3) Mother maiden name"<<std::endl;

    std::cin>>SecurityQuestionCheck;
    switch (SecurityQuestionCheck)
    {
        case 1:
        {
            std::system("clear");
            std::cout << "First pet name: ";
            std::cin >> SecurityQuestion;
            break;
        }
        case 2:
        {
            std::system("clear");
            std::cout << "Who was your first kiss: ";
            std::cin >> SecurityQuestion;
            break;
        }
        case 3:
        {
            std::system("clear");
            std::cout << "What is your mothers maiden name: ";
            std::cin>>SecurityQuestion;
            break;
        }
        default:
        {
            std::system("clear");
            std::cout << "Invalid option" << std::endl;
            CreateAccount();
        }
    }


    std::string salt = GenerateSalt();  // generate random salt

    std::ofstream Userfile("account.key");  // REMOVE app mode – overwrite for one user
    if (Userfile.is_open()) {
        Userfile << salt << "\n";                         // Line 1: salt
        Userfile << Encrypt(salt + Username) << "\n";     // Line 2
        Userfile << Encrypt(salt + UserPassword) << "\n"; // Line 3
        Userfile << SecurityQuestionCheck << "\n";        // Line 4
        Userfile << Encrypt(salt + SecurityQuestion) << "\n"; // Line 5    
        Userfile.close();
    } else {
        std::cerr << "Failed to open file.\n";
        return false;
    }

    return true;
}


bool LoadPasswords()
{
    std::ifstream PasswordFile("passwords.key");
    if (PasswordFile.is_open())
    {
        int currentline = 0;
        std::string line;

        while(std::getline(PasswordFile, line))
        {
        
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                Websites.push_back(line.substr(0, colonPos));
                DecryptedSavedPasswords.push_back(Decrypt(line.substr(colonPos + 1)));
            }
        }
    }
    else
    {
        std::cout << "Password file failed to open this could be due to no passwords being stored"<<std::endl;
        return false;
    }
    return true;
}

std::string Encrypt(std::string UnencryptedText)
{
    std::string EncryptedTextBinary;
    CBC_Mode<AES>::Encryption Encryption;
    Encryption.SetKeyWithIV(key, sizeof(key), iv);

    StringSource(UnencryptedText, true,
        new StreamTransformationFilter(Encryption,
            new StringSink(EncryptedTextBinary)
        )
    );

    // Encode to hex for safe storage
    std::string EncryptedTextHex;
    StringSource(EncryptedTextBinary, true,
        new HexEncoder(new StringSink(EncryptedTextHex))
    );

    return EncryptedTextHex;
}

std::string Decrypt(const std::string& EncryptedTextHex)
{
    std::string EncryptedTextBinary;
    std::string Plaintext;

    try {
        // Decode hex before decrypting
        StringSource ss(EncryptedTextHex, true,
            new HexDecoder(
                new StringSink(EncryptedTextBinary)
            )
        );

        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv);

        StringSource ss2(EncryptedTextBinary, true,
            new StreamTransformationFilter(decryption,
                new StringSink(Plaintext)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
    }

    return Plaintext;
}


//YES I USED CHATGPT FOR THIS NOOOO I DGAF
std::string GenerateSalt(size_t length) {
    AutoSeededRandomPool prng;
    SecByteBlock salt(length);
    prng.GenerateBlock(salt, salt.size());

    std::string encoded;
    StringSource(salt, salt.size(), true,
        new HexEncoder(new StringSink(encoded))
    );

    return encoded;
}

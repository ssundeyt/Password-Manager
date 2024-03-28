#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h>
#include <hex.h>
#include <pwdbased.h>
#include <sha.h>
#include <limits>
#include <cstdlib>
#include <algorithm>
#define NOMINMAX
#include <windows.h>

// the fucking passwords and master passwords are stored in the project files. we need to change this. perhaps using the 
// registry or just hiding them somewhere...

// global master password
std::string masterPassword;

// SHA-256 hash
std::string simpleHash(const std::string& input) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource s(input, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));

    return digest;
}

// clear the screen after each operation to prevent the terminal from getting clustered
void pauseAndClear() {
    std::cout << "Press ENTER to clear...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// clear without prompting
void forceClear() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// conduct a check if it is the first run by checking if a file called isFirsRun.txt is present. Also using this file to store the
// hashed master pw for simplicity
void setOrVerifyMasterPassword() {
    std::ifstream checkFirstRun("isFirstRun.txt");
    if (!checkFirstRun.good()) {
        // if first run then create a new master pw and store it hashed in isFirstRun
        std::cout << "Setting up a new master password: ";
        std::cin >> masterPassword;
        std::ofstream out("isFirstRun.txt");
        out << simpleHash(masterPassword);  // hashing master pw
        out.close();
    }
    else {
        // subsequent runs: verify the master pw
        std::string storedHash;
        checkFirstRun >> storedHash;
        checkFirstRun.close();

        std::string enteredPassword;
        std::cout << "Enter the master password: ";
        std::cin >> enteredPassword;

        if (simpleHash(enteredPassword) != storedHash) {
            std::cerr << "fuck you" << std::endl;
            exit(1);
        }
        masterPassword = enteredPassword;
    }
}

// function to change master pw. Ask for old master pw, new and confirm 
void changeMasterPassword() {
    std::string oldPassword, newPassword, confirmPassword;
    std::cout << "Enter old master password: ";
    std::cin >> oldPassword;

    std::ifstream infile("isFirstRun.txt");
    std::string storedHash;
    infile >> storedHash;
    infile.close();

    if (simpleHash(oldPassword) != storedHash) {
        std::cerr << "Incorrect old master password. Exiting..." << std::endl;
        Sleep(1000);
        forceClear();
        return;
    }

    std::cout << "Enter new master password: ";
    std::cin >> newPassword;
    std::cout << "Confirm the new master password: ";
    std::cin >> confirmPassword;

    if (newPassword != confirmPassword) {
        std::cerr << "Passwords dont match. Exiting..." << std::endl;
        Sleep(1000);
        forceClear();
        return;
    }

    // update the stored master password hash
    std::ofstream out("isFirstRun.txt", std::ofstream::trunc);  // overwrite isFirstRun.txt
    out << simpleHash(newPassword);
    out.close();

    masterPassword = newPassword;
    std::cout << "Master password has been changed." << std::endl;
    Sleep(2000);
    forceClear();
}

// encode passwords
std::string EncodeToHex(const std::string& str) {
    std::string encoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );
    return encoded;
}

// decode passwords
std::string DecodeFromHex(const std::string& str) {
    std::string decoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(decoded)
        )
    );
    return decoded;
}

// encryption with IV from crypto++. dont know how well crypto++ works but a fun learning project
void DeriveKeyAndIV(const std::string& masterPassword, const std::string& salt, CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]) {
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    CryptoPP::byte derived[CryptoPP::AES::DEFAULT_KEYLENGTH + CryptoPP::AES::BLOCKSIZE];

    kdf.DeriveKey(
        derived, sizeof(derived),
        0x00,
        (const CryptoPP::byte*)masterPassword.data(), masterPassword.size(),
        (const CryptoPP::byte*)salt.data(), salt.size(),
        1024, 0
    );

    std::memcpy(key, derived, CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::memcpy(iv, derived + CryptoPP::AES::DEFAULT_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
}

// encrypt funct
std::string Encrypt(const std::string& plain, const CryptoPP::byte key[], const CryptoPP::byte iv[]) {
    std::string cipher;

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher)
            )
        );
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << ex.what() << std::endl;
    }

    return cipher;
}

// decrypt func to read inside "retrieve password"
std::string Decrypt(const std::string& cipher, const CryptoPP::byte key[], const CryptoPP::byte iv[]) {
    std::string plain;

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

        CryptoPP::StringSource s(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(plain)
            )
        );
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << ex.what() << std::endl;
    }

    return plain;
}

// a function to generate a safe(?) password
std::string generatePassword() {
    // this function is way to simple...
    const std::string lowerChars = "abcdefghijklmnopqrstuvwxyz";
    const std::string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string specialChars = "!@#$%^&*";
    const int passwordLength = 12; // minimum length should be changed to increase complexity

    std::string password;

    // ensure the generated pw contains at least one char from the sets
    password += lowerChars[rand() % lowerChars.size()];
    password += upperChars[rand() % upperChars.size()];
    password += digits[rand() % digits.size()];
    password += specialChars[rand() % specialChars.size()];

    // fill rest with randoms from set 
    std::string allChars = lowerChars + upperChars + digits + specialChars;
    while (password.size() < passwordLength) {
        password += allChars[rand() % allChars.size()];
    }

    // shuffle chars
    std::random_shuffle(password.begin(), password.end());

    return password;
}

// list the websites and apps to make it more user friendly and organized 
void listWebsites() {
    std::ifstream infile("passwords.txt");
    if (!infile.is_open()) {
        std::cerr << "unable to open the passwords file." << std::endl;
        return;
    }

    std::string line;
    std::cout << "Stored websites/apps:" << std::endl;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string website;
        if (std::getline(iss, website, '|')) {
            std::cout << "- " << website << std::endl;
        }
    }

    infile.close();
}

// boolean returns true if website exists, if it does then user cannot enter that same name when adding new pw
bool doesWebsiteExist(const std::string& website) {
    std::ifstream infile("passwords.txt");
    if (!infile.is_open()) {
        std::cerr << "unable to open passwords file." << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string storedWebsite;
        if (std::getline(iss, storedWebsite, '|')) {
            if (storedWebsite == website) {
                return true;
            }
        }
    }

    return false;
}

bool isSpecialCharacter(char ch) {
    // list of special chars
    std::string specialChars = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~";
    return specialChars.find(ch) != std::string::npos;
}

// evaluate strength using a points system
int checkPasswordStrength(const std::string& password) {
    int strengthScore = 0;

    // funcs to determine strength
    int length = password.length();
    if (length >= 8) strengthScore += 1;
    if (length >= 12) strengthScore += 2;

    int uppercaseCount = std::count_if(password.begin(), password.end(), ::isupper);
    if (uppercaseCount > 0) strengthScore += 2;

    int lowercaseCount = std::count_if(password.begin(), password.end(), ::islower);
    if (lowercaseCount > 0) strengthScore += 2;

    int digitCount = std::count_if(password.begin(), password.end(), ::isdigit);
    if (digitCount > 0) strengthScore += 2;

    int specialCharCount = std::count_if(password.begin(), password.end(), isSpecialCharacter);
    if (specialCharCount > 0) strengthScore += 3;

    return strengthScore;
}

void addPassword() {
    std::string website, username, password;
    int passwordChoice;

    // i changed this to stop prompting for the master pw every  time we add a password, it just uses the hashed master pw 

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::byte salt[CryptoPP::AES::BLOCKSIZE];
    rng.GenerateBlock(salt, sizeof(salt));
    std::string encodedSalt = EncodeToHex(std::string((char*)salt, sizeof(salt)));

    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    DeriveKeyAndIV(masterPassword, std::string((char*)salt, sizeof(salt)), key, iv);  // use global masterPassword

    forceClear();
    std::cout << "Enter the website/app's name: ";
    std::cin >> website;

    if (doesWebsiteExist(website)) {
        std::cerr << "a password for " << " already exists. Do you want to overwrite it [y/n]";
        char response;
        std::cin >> response;
        if (response != 'y' && response != 'Y') {
            std::cout << "operation cancelled" << std::endl;
            Sleep(1000);
            forceClear();
            return;
        }
    }

    std::cout << "Enter the username: ";
    std::cin >> username;

    std::cout << "Do you want to 1. enter password manually, or 2. generate a random secure password? [1 or 2]: ";
    std::cin >> passwordChoice;

    if (passwordChoice == 1) {
        std::cout << "Enter password: ";
        std::cin >> password;

        int strength = checkPasswordStrength(password);

        if (strength < 7) {
            std::cout << "\033[31mPassword is weak\033[0m" << std::endl;
        }
        else if (strength >= 11) {
            std::cout << "\033[32mPassword is strong\033[0m" << std::endl;
        }
        else if (strength >= 7) {
            std::cout << "\033[33mPassword is moderate\033[0m" << std::endl;
        }
        std::cout << "\033[0m";
    }
    else if (passwordChoice == 2) {
        password = generatePassword();
        std::cout << "Generated password: " << password << std::endl;
    }
    else {
        std::cerr << "invalid choice. Exiting..." << std::endl;
        Sleep(1000);
        forceClear();
        return;
    }

    // just uses already defined variables
    std::string encryptedUsername = Encrypt(username, key, iv);
    std::string encryptedPassword = Encrypt(password, key, iv);

    std::string encodedUsername = EncodeToHex(encryptedUsername);
    std::string encodedPassword = EncodeToHex(encryptedPassword);
    std::string encodedIV = EncodeToHex(std::string((char*)iv, CryptoPP::AES::BLOCKSIZE));

    std::ofstream outfile("passwords.txt", std::ios_base::app);
    if (!outfile.is_open()) {
        std::cerr << "failed to open the passwords file." << std::endl;
        return;
    }
    outfile << website << "|" << encodedSalt << "|" << encodedUsername << "|" << encodedPassword << "|" << encodedIV << std::endl;
    outfile.close();

    std::cout << "Credentials added!" << std::endl;

    Sleep(4000);
    forceClear();
}


void retrievePassword() {
    std::string selectedWebsite;

    listWebsites();

    std::cout << "Enter the website/app's name to show password for: ";
    std::cin >> selectedWebsite;

    std::ifstream infile("passwords.txt");
    if (!infile.is_open()) {
        std::cerr << "unable to open the passwords file." << std::endl;
        Sleep(1000);
        return;
    }

    // i use salt for added security. it reads the file according to how we set up the storing mechanism : webiste|encodedsalt|encodedusername etc.
    std::string line, website, encodedSalt, encodedUsername, encodedPassword, encodedIV;
    bool found = false;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        if (std::getline(iss, website, '|') && std::getline(iss, encodedSalt, '|') &&
            std::getline(iss, encodedUsername, '|') && std::getline(iss, encodedPassword, '|') &&
            std::getline(iss, encodedIV, '|') && website == selectedWebsite) {
            found = true;

            std::string salt = DecodeFromHex(encodedSalt);
            std::string iv = DecodeFromHex(encodedIV);
            CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
            DeriveKeyAndIV(masterPassword, salt, key, (CryptoPP::byte*)iv.data());  // use global masterPassword

            std::string decryptedUsername = Decrypt(DecodeFromHex(encodedUsername), key, (const CryptoPP::byte*)iv.data());
            std::string decryptedPassword = Decrypt(DecodeFromHex(encodedPassword), key, (const CryptoPP::byte*)iv.data());

            std::cout << "Website/App: " << "\033[35m" << website << "\033[0m" << std::endl;
            std::cout << "Username: " << "\033[35m" << decryptedUsername << "\033[0m" << std::endl;
            std::cout << "Password: " << "\033[35m" << decryptedPassword << "\033[0m" << std::endl;

            pauseAndClear();
            break;
        }
    }

    infile.close();

    if (!found) {
        std::cout << "Credentials for " << selectedWebsite << " not found!" << std::endl;
        Sleep(2000);
        forceClear();
    }
}

// this function could perhaps be written a bit better and sexier...
void deletePassword() {
    // List all websites/apps before deletion
    listWebsites();

    std::string websiteToDelete;
    std::cout << "Enter the website/app's name to delete: ";
    std::cin >> websiteToDelete;

    std::ifstream infile("passwords.txt");
    if (!infile.is_open()) {
        std::cerr << "failed to open the passwords file." << std::endl;

        Sleep(1000);
        forceClear();
        return;
    }

    std::vector<std::string> lines;
    std::string line;
    bool found = false;

    // read all lines and store them, except the one to delete
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string website;
        if (std::getline(iss, website, '|')) {
            if (website != websiteToDelete) {
                lines.push_back(line);  // keep the line if it's not the one to delete
            }
            else {
                found = true;
            }
        }
    }

    infile.close();

    if (!found) {
        std::cout << "website not found" << std::endl;

        Sleep(2000);
        forceClear();
        return;
    }

    // rewrite the file without the deleted website. i dont know why i decided to overcomplicate it so much... there is probably a better way 
    std::ofstream outfile("passwords.txt");
    if (!outfile.is_open()) {
        std::cerr << "failed to open the passwords file." << std::endl;

        Sleep(1000);
        forceClear();
        return;
    }

    for (const auto& savedLine : lines) {
        outfile << savedLine << std::endl;  // write back all lines except the deleted one
    }

    outfile.close();

    std::cout << "Credentials for " << websiteToDelete << " deleted." << std::endl;

    Sleep(2000);
    forceClear();
}

void displayMenu() {
    int choice;
    do {
        std::cout << "\033[35mdeveloped by ssundeyt\033[0m\n";
        std::cout << "Password Manager Menu:\n";
        std::cout << "1. Add password\n";
        std::cout << "2. Display password\n";
        std::cout << "3. Delete password\n";
        std::cout << "4. Change master password\n";
        std::cout << "5. EXIT\n";
        std::cout << "Enter choice [number]: ";
        std::cin >> choice;

        // check if input operation failed due to receiving wrong data type
        if (std::cin.fail()) {
            std::cin.clear();
            // ignores rest of wrong input and clear input buffer
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "\nInvalid input. enter a number\n";
            Sleep(2000);
            forceClear();
            continue;
        }

        switch (choice) {
            case 1: addPassword(); break;
            case 2: retrievePassword(); break;
            case 3: deletePassword(); break;
            case 4: changeMasterPassword(); break;
            case 5: std::cout << "byebye\n"; break;
        }
    } while (choice != 5);
}

int main() {
    setOrVerifyMasterPassword(); // run this first since nothing but the initial loading is dependant on it ....

    displayMenu();

    return 0;
}
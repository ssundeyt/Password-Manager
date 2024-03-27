# Password manager in C++
an attempt to expand my c++ skills into encryption using cryptopp

once im back in my dorm room after easter ill keep working on it 

**Features**

- lets user input/display/delete passwords and encrypts/decypts them using a salt and sha-256
- added a function to generate a random secure password
- a masterpassword for the app stored in isFirstRun.txt
- if its the first run then check if isFirstRun.txt doesnt exist then it will create one and prompt user to create master password

# Agenda / improvements-to-be-made

- a GUI like a windows application instead of terminal
- add a password strength checker
- a more secure storage for passwords
- automatic timeout/logout
- backup and restore function
- password history function
- 2FA
- password sharing
- security audit
- cross-platform (maybe using swift for IOS)
- user customizable settings
- secure note storage
- import / export function
- browser extention/integration(!!!)
- some sort of captcha

I am an economy student and this is my hobby so it may take some time to finalize this project. i ask your patient if youre serious about using this app.

this is my biggest project so far and intend to share the entire source code in the future!

furthermore, i cant keep doing everything inside the main.cpp (or passwordmanager.cpp as for now) in the future. please do adequate pull requests if needed

# run now?
if you want to run this project now as it is you need to download and compile cryptopp and add it to your linker, otherwise it will just crash.

you also need to set the adequate include directory and include the compiled cryptlib.lib in your linker dependencies.

if you want to use mingw just pacman install cryptopp and link it directly in the command 

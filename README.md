# Password manager in C++
A password manager that uses a safe encryption method to store and write passwords that the user inputs.

**Update a0.0.2**

- Fixed the bug with the infinite loop caused from incorrect input buffer handling
- Added a better console clear feature
- checked off the password strength checker. Now displays the security of the password in 'weak', 'moderate' and 'strong' based off a few tests of the chars and length

# Agenda / improvements-to-be-made

- add a password strength checker //check!
- a GUI like a windows application instead of terminal
- add a password changer instead of needing to redo the entire process
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

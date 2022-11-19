# Questions from Week 1
Link to questions: https://hackmd.io/EU6tnzE2SmqIH-XC5E7JhA

## Ch 2:

Q3. 30C2 or 435

Q4. It does not prove that Alice saw the message and chose to sign. Her key could have been
compromised instead and the attacker could have sent the signature on her behalf.

Q5. No, the scheme could still be vulnerable to a different form of attack.

Q6. n should be 256. This is because we have 2^256 different keys to choose from. By the
birthday paradox, the attacker can break the system after seeing just sqrt(2^256) transactions. And
sqrt(2^256) = 2^128


## General questions:

### Suppose you read about RSA encryption and wanted to find it’s standard specification. Where would you look?

Maybe this? https://www.rfc-editor.org/rfc/rfc8017
NIST is likely also a good place.

### Find two libraries for each of RSA, TLS/SSL, and AEAD. Evaluate the maturity each library, and skim the code. What about the library structure makes sense? How is their documentation?

RSA
https://github.com/RustCrypto/RSA
- Doesn't look that mature by looking at their road map (they have been audited though)
     - Also does not look that active
- Documentation looks pretty good! I like how they linked to papers that were used for the
algorithms
- Very simple structure, everything is just dumped in src without sub directories
- Doesn't look like there are that many tests. There are just two integration tests that I can
see: pkcs8.rs and pkcs1.rs. I am not sure if these two are sufficient but they do seem to test
the entire workflow so quite possibly yes.

https://github.com/hakhenaton/rsa-oaep-pss
- The only other other RSA library I could find, which just looks like someone's hobby project
lol.
- The documentation looks pretty sparse but it does show how to do the basics of key gen,
encryption and decryption.
- Overall very not mature since it is not even a month old.
- Organization wise everything is just in the src crate without subdirectories


TLS/SSL
https://github.com/rustls/rustls
- Looks quite mature, has been around for at least 7 years based on the commits
- It is audited: https://cure53.de/pentest-report_rustls.pdf
- Documentation seems pretty good: https://docs.rs/rustls/latest/rustls/
- Just looking at the top level directories leave a few questions:
    - What does 'fuzz' mean? Looking at the related code doesn't answer much.
    - Why are keys stored under 'bogo'?
- Having a client and server directory in `src` makes sense
- Having a directory for messages makes sense

https://github.com/sfackler/rust-native-tls/
- This one looks a lot simpler than the previous. It has also been around for a while, around 5
years.
- The structure is just the standard lib.rs with a test.rs for the most part.
- There are three files for each of the TLS implementations accross each platform
- Documentation is a bit sparse in the code itself

AEAD
https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
- It is a lot simpler than I thought it was going to be. All code in the lib.rs.
    - I think this is the case since most of the logic is in here: https://lib.rs/crates/aes
- Is audited, so mature in that respect. And has been around for 3 years
- Uses the standard rust traits for the API, which is good for interoperability and switching
out impls if necessary

https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
- also audited
- Uses ChaCha20 instead of AES, which apparently hasn't been approved by NIST but is still
widely used
- Maturity wise seems similar to the other
- Pretty simple structure, makes sense. They implement the standard API which as said makes it
easy for users to consume. All types are defined in lib.rs.
- Great docs, very detailed.


### Benchmark the speed of an algorithm in the two different implementations with Criterion.

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running benches/week1.rs (target/release/deps/week1-451d16280bbb9934)

     lib1 generate keys      time:   [182.96 ms 194.21 ms 205.67 ms]

Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

     lib1 encrypt           time:   [192.29 µs 194.68 µs 197.27 µs]

Found 15 outliers among 100 measurements (15.00%)
  7 (7.00%) high mild
  8 (8.00%) high severe

     lib1 decrypt            time:   [1.7214 ms 1.7464 ms 1.7726 ms]

Found 9 outliers among 100 measurements (9.00%)
  9 (9.00%) high mild

     lib 2 generate keys     time:   [211.66 ms 229.09 ms 246.93 ms]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

     lib 2 encrypt           time:   [137.39 µs 139.83 µs 142.65 µs]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

     lib 2 decrypt           time:   [9.7988 ms 9.8701 ms 9.9718 ms]
Found 12 outliers among 100 measurements (12.00%)
  8 (8.00%) high mild
  4 (4.00%) high severe


### You’re implementing a Tweakable Encryption scheme. You need to know what standard API users will expect. Find a reference for the standard API and write the function signatures for encryption and decryption.
See src/week1/mod.rs

### You want to understand a paper on a new polynomial commitment scheme, but you’ve been trying for more than an hour, and the math is over your head. What do you do?
First go for a walk and see if time is the solution. If that doesn't work I'd ask the unclock study group to see if anyone could help.

### Implement Vigenere Cipher
See src/week1/mod.rs


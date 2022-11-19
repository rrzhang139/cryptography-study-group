# Questions from Week 1

## Ch 2:

Q3. 30C2 or 435

Q4. It does not prove that Alice saw the message and chose to sign. Her key could have been
compromised instead and the attacker could have sent the signature on her behalf.

Q5. No, the scheme could still be vulnerable to a different form of attack.

Q6. n should be 256. This is because we have 2^256 different keys to choose from. By the
birthday paradox, the attacker can break the system after seeing just sqrt(2^256) transactions. And
sqrt(2^256) = 2^128


## General questions:

1. Maybe this? https://www.rfc-editor.org/rfc/rfc8017
NIST is likely also a good place.

2. RSA
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

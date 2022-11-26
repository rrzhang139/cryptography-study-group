# Questions from Week 2
Link to questions: https://uncloak.org/courses/rust+cryptography+engineering/course-2022-11-25+Session+2+Notes

## Chapter 3
1. 64 bit blocks and 80 bit key. 2^80 different keys. Number of possible 64 bit blocks is 2^64. Therefore, lookup table size is 2^64 x 80;

2.  DES key is 56 bits. So there are 2^56 possible keys for DES. Therefore, given the speed of 2^-26 seconds for a single ecryption/decryption,
it would take us 2^(56 - 26) = 2^30 seconds = 298,261.62 hours.

If we had 2^14 processors, it would take 2^16 seconds, which is 18.2 hours.

3.
E(K, P) = F(F(R, K1) xor L, K2) xor R

C1 = F(R, K1) xor L
C2 = F(C1, K2) xor R

Cipher text looks like C1 | C2

We have many pairs L|R and C1 | C2 that we know of.

Then we can perform an exhaustive search over K1, while fixing K2 to some arbitrary value. This takes at most 2^48 iterations. We stop once we confirm that
the found C1 makes the one we have for the given input.

Now we just use the K1 we found and exhaustive search over K2. This takes at most 2^48 iterations. In total, this takes 2^49 iterations in the worst case.

## Chapter 4
1. This is not a good padding scheme because 0 is included as a valid number of padding bytes. This is an issue as it makes it impossible to reverse the padding because in the
case of n = 0, it won't be clear how many bytes were added since P || 0 is the same as P.

2. Since they are both encrypted with the same nonce, and we know one of the plaintexts, we can compute:

C1 xor C2 = P1 xor K1 xor P2 xor K2 = P1 xor P2 xor E(K, nonce || i) xor E(I, nonce || j) TODO: Come back to this.



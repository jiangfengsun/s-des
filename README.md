# s-des
A simplified DES (S-DES) as descriped in the attachment (sdes-intro.pdf) to illustrate DES encryption and decryption.

Usage:

/***********************************************************************

sdes [-e] [-d] [text] [key]

<br/>
OPTION:

-e (Encryption)

-d (Decryption)


INPUT:

text (8-bit plaintext or ciphertext)

key (10-bit key)


Usage (encryption):

$sdes -e 11111111 0000011111

Ciphertext: 11100001


Usage (decryption):

$sdes -d 11100001 0000011111

Plaintext: 11111111

***********************************************************************/

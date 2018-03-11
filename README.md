# s-des
A simplified DES (S-DES) as descriped in the attachment (sdes-intro.pdf) to illustrate DES encryption and decryption.

**Usage:**

/***********************************************************************
<br/>
sdes [-e] [-d] [text] [key]
<br/>
<br/>
OPTION:<br/>
-e (Encryption)<br/>  
-d (Decryption)<br/>
<br/>
<br/>
INPUT:<br/>  
text (8-bit plaintext or ciphertext)<br/>  
key (10-bit key)<br/>
<br/>
<br/>
Usage (encryption):<br/>
```
$sdes -e 11111111 0000011111
```
Ciphertext: 11100001<br/>
<br/>
<br/>
Usage (decryption):<br/>
```
$sdes -d 11100001 0000011111
```
Plaintext: 11111111<br/>
***********************************************************************/

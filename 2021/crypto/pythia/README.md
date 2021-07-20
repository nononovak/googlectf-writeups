
# PYTHIA

> Yet another oracle, but the queries are costly and limited so be frugal with them.

[Attachment](https://github.com/google/google-ctf/blob/master/2021/quals/crypto-pythia/challenge/server.py) `pythia.2021.ctfcompetition.com 1337`

## Analysis

This problem provided a Python server which gave you three options - select a key, provide a password, or decrypt some ciphertext. The password was randomly generated on each connection and nine characters long - split into three-character chunks. An AES key was derived from each chunk and used for the trial AES decryption. Finally, the server only allowed 150 operations total.

A simple back-of-the-envelope calculation showed that there were 26^3 possible values for each of the three password chunks so a brute force solution was impractical. Furthermore, the server throttled requests at ten seconds intervals.

## Solution

This solution relied on a new technique posted in a [2020 research paper titled "Partitioning Oracle Attacks"](https://eprint.iacr.org/2020/1491.pdf). The paper describes a new technique where an AEAD ciphertext can be generated which decrypts using multiple encryption keys. In particular, a section on AES GCM mode and [some reference code which implements the techinque](https://github.com/julialen/key_multicollision/blob/main/collide_gcm.sage) make it easy to recreate the solution.

With the reference implementation (written in sage), a Python script which hooks up the `multi_collide_gcm()` function with the target server was written to partition the potential AES keys (derived from three-character values passwords) and then submit requests to the server. With all the plumbing in place, the script (`solve.py` in this folder) does about 20 minutes of pre-computation followed by about 10 minutes of interaction with the server (remember, there is a 10-second delay on each request). A `Dockerfile` is also provided which will build/run the script with an appropriate `sage` and `python` environment.

```
$ docker build -t pythia-solution .
$ docker run --rm -it pythia-solution
14:32:03 [+] Creating partition 0/16
14:32:03 [+] Generating partition for 1099 ciphertexts
14:32:51 [+] Saving 1 generated ciphertexts

...

14:51:35 [+] Saving 48 generated ciphertexts
14:51:36 [+] Connecting to ('pythia.2021.ctfcompetition.com', 1337)
14:51:47 [+] Partition 0/16 .. False

...

15:01:21 [*] Flag response: Checking...
ACCESS GRANTED: CTF{gCm_1s_n0t_v3ry_r0bust_4nd_1_sh0uld_us3_s0m3th1ng_els3_h3r3}

You have 94 trials left...

What you wanna do?
1- Set key
2- Read flag
3- Decrypt text
4- Exit
>>>
15:01:21 [+] Saving 48 generated ciphertexts
```


# Onion Builder

In the route builder challenge, you learned how to generate the data
that we put in _onion payloads_ that provide hops in the route with
the information they need to forward payments. In this challenge, 
you'll "wrap" these payloads in a lightning onion using bolt04.

The use of onions in lightning is important because:
* It provides privacy guarantees similar to tor; forwarding nodes only
  know the identity of the nodes on either side of them, not the sender
  or receiver.
* It provides integrity, ensuring that forwarding node can't claim money
  that isn't theirs!

May the HMACs be ever in your favor!

![image](layers.jpg)

When you're a LN protocol developer, all you get to implement a new 
feature is:
* The [specification](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
  outlining how to implement a feature.
* [Test vectors](https://github.com/lightning/bolts/blob/master/bolt04/onion-test.json)
  that you can use to test your code.

We suggest that you consult the following resources as well:
* [Christian Decker - Onion Deep Dive](https://www.youtube.com/watch?v=D4kX0gR-H0Y)
* [Elle Mouton - Sphinx Packet Construction](https://ellemouton.com/posts/sphinx/)

## Assignment

Write a program that accepts a json file containing the keys and 
payloads for a lightning payment. Your program should accept two
arguments:
* 0: An absolute path to the directory that you should write your 
     output file to.
* 1: An absolute path to `input.json` (see format below)

You may import (or copy and attribute) code for the cryptographic
primitives used in onion wrapping, such as:
* ECDH
* HMAC Generation
* XOR
* ChaCha20

Your job is to use these primitives to create a valid onion packet for
the provided route.

### Input

Your program should accept two command line arguments:
* 0: An absolute path to the directory to write your output files.
* 1: An absolute path to `input.json` (see format below)

```
{
    "session_key": "4141414141414141414141414141414141414141414141414141414141414141",
    "associated_data": "4242424242424242424242424242424242424242424242424242424242424242",
    "hops": [
        {
            "pubkey": "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            "payload": "1202023a98040205dc06080000000000000001"
        },
        {
            "pubkey": "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
            "payload": "52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f"
        },
        {
            "pubkey": "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
            "payload": "12020230d4040204e206080000000000000003"
        },
        {
            "pubkey": "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
            "payload": "1202022710040203e806080000000000000004"
        },
        {
            "pubkey": "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
            "payload": "fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
        }
    ]
}
```

Source: [bolt04 test vectors](https://github.com/lightning/bolts/blob/c41536829c1461fe5109183ce8a7f88f5c81348b/bolt04/onion-test.json).

### Output

You will be expected to hex encode your onion and write it to 
`output.txt` in the output path argument. This output is required, and
you will not pass the assignment without it!

Example `output.txt`:
```
0002eec7245d6b7d2ccb30380bfbe2a36...
```

### Submission

Once you have completed the steps, submit the following to the 
submissions folder:
* The source code for your solution.
* Bash script in run.sh that will run your program with the arguments provided.
  * Expect this script to be run from the parent directory of 
    submissions i.e: `./submissions/run.sh {output csv path} {input.csv path}`
    with the arguments provided.

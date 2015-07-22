## microcorruption

This repo contains my late solutions to the last levels of the microcorruption CTF.  
I had never seriously written a shellcode before, so this was incredibly fun and interesting.

I only kept some notes of the 3 levels that I found more challenging: Lagos, Chernobyl and Hollywood.  

#### Lagos 
I found after the fact that Lagos was actually pretty easy to solve with the right instructions, but I couldn't find them so I basically couldn't use any instructions that wrote to memory.
I ended up writing a 2 stage solution that first disables all the protections through some ROP chaining and then load a second stage, which uses the newly acquired arbitrary code execution to trivially unlock the door.

#### Chernobyl
For Chernobyl the main difficulty factor is the substantial amount of code to read, but then the vulnerabilities in free/malloc are pretty straightforward to exploit.
It was much more an exercise in reverse engineering than shellcoding/exploitation in my view, but still fun.

#### Hollywood
And finally Hollywood. This one was a really interesting learning experience, and the only one for which I actually had to write code.  
The web disassembler was starting to feel too slow and impractical, so I had to do this one with IDA, and I don't think I could have finished the level without it.  
After reverse engineering the main loop that decrypts and runs small code buffers I wrote a Python script to decrypt the code, and loaded that new code into IDA. 
Then I wrote an IDA-Python script that analyzes the decrypted code by following the return addresses to find all the code buffers and create functions for them.
I updated that script to give me a nice disassembly of the recontructed decrypted code, and I now had a third final file with the real algorithm that was hidden behind all this obfuscation.  
And all that was left was finding a password that would collide with the algorithm's hardcoded hash.  
I tried a dictionnary attack first, but it was not in rockyou.txt, so I went with an actual bruteforce and found it in a bit under 2 hours!  
All the code is in the hollywood folder.

I'm now eagerly waiting for http://www.starfighters.io



# Secure Aggregation



## dependencies

 - pycryptodome


## cryptographic primitives

 - secret sharing
 - key aggrement
 - authenticated encryption
 - pseudorandom genarator
 - signature scheme


## test result

|                     |server |client |
|---------------------|-------|-------|
|setup                |$\surd$|$\surd$|
|AdvertiseKeys        |$\surd$|$\surd$|
|ShareKeys            |$\surd$|$\surd$|
|MaskedInputCollection|$\surd$|$\surd$|
|ConsistencyCheck     |$\surd$|$\surd$|
|Unmasking            |$\surd$|$\surd$|


## minor problem

 1. secure parameter : 1024
 2. udp : insecure channel
 3. secret sharing : $O(n^3)$
 4. PRG : built-in
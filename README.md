## Shamir Secret Sharing manual

### Preconditions

---

OpenSSL 1.1.1 

clang/gcc



### Basic Data Structures

---

user should operate shm_key_share list, each node contains 
 - x coordinate
 - y coordiante
 - public p, finite field
 - public n, minimal number of shares
 - encoding b, 2 for binary, 16 for hex
 - pointer to next node

above are accessiable via shm_key_share_\*/shm_key_share_set_\*

### Use

---


1. creating new keys

 - user could use shm_key_share_new to allocate new memory space and use shm_keygen to generate new key shares.
 - security_lv indicates key length, finite field always has one bit larger than key length, eg GF(2^129)
 - user should set minimal number of shares required to recreat the key, and total number of shares to create.
 - if user provides master secret to keygen, keygen will use the master secret to generate key shares.
 - if on master secret provided, keygen will generate a random key that its MSB is always set. (BN_RAND_TOP_ONE)
 - user could recover the key via shm_recover_secret,
first use shm_recover_secret(NULL, &len, ks, min) to obtain the length of the secret, then use shm_recover_secret(secret, &len, NULL, 0) to obtain the secret.
 - use could generate more shares via shm_create_more_key_share(\*)
 - shm_cleanup should be called after any function, funcions marked by \* should call twice on each list.


### Return Value

---

shm_key_share_new

shm_key_share_next

shm_key_share_x

shm_key_share_y

shm_key_share_p 

returns data pointer, NULL on error

other functions return int, see shamir.h for error def


### Misc

---

Compiling with -D DEBUG=1 to use test case GF(1613)








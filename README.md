# PRTH-Crypt v4.2:
A high-performance, constant-time password hasher using a ChaCha20 sponge construction and Base72 encoding, hardened against side-channel attacks.
(use at own risk)
## Compile
# Clone the repo
git clone https://github.com/Partakithware/PRTH-CRYPT.git
cd PRTH-CRYPT

# How to Compile
gcc -O3 PRTHCRYPT.c -o prth

# Run a test hash
./prth hash "mypassword"

## What Changed from v4.0

**v4.0 was broken.** The "ORAM" implementation still leaked cache lines.

### PBKDF2-Style (RECOMMENDED)

**Build:**
```bash
gcc -O3 PRTHCRYPT.c -o prth
```

**What it does:**
- Pure iteration (no memory pool)
- ChaCha20 mixing function
- 100% data-independent (ZERO timing leaks possible)

**Performance:**
- ~100 ms for 12.5M iterations [Intel® Core™ i7-7820HQ × 8] (depending on hardware, so make sure to test iterations to fit)
- should be the same speed as bcrypt/PBKDF2
- Can scale to 100M+ iterations if needed

**Security:**
- ✅ Zero timing attacks (no secret-dependent memory access)
- ✅ Proven primitives (ChaCha20)
- ✅ Simple implementation (less attack surface)
- ⚠️ Vulnerable to GPU/ASIC attacks (like all non-memory-hard functions)

**When to use:**
- **Most production deployments**
- Web applications
- API authentication
- Any normal password hashing

**Defense against GPUs:**
Just crank up the work factor (Max 100M). Modern GPUs are ~1000x faster than CPUs, so:
- CPU: if 12.5M iterations = 100ms
- GPU: 12.5M iterations = (too fast!)

**Honest assessment:** This is **exactly what PBKDF2 does**. 
PRTHCRYPT's unique contribution is the ChaCha20-based mixing and Base72 encoding. It's a solid, secure password hasher.

## Recommendations by Use Case

### Web Application / API (99% of use cases)

**Use: PBKDF2 mode**

```
gcc -O3 PRTHCRYPT.c -o prth
./prth hash "user_password" 384 12500000  # 12.5M iterations minimum preference
```

- Secure against timing attacks
- Fast enough for user experience
- Just scale iterations if GPUs get faster

### Higher-Security / Offline Storage
**Use: PBKDF2 mode with higher iterations**
```
./prth hash "master_password" 512 50000000  # 50M iterations+
```

### Research / Benchmarking
...

## Migration from v3.3

All hash formats are **forward compatible**:
```
# Hashes from v3.3, v4.0, v4.1 PBKDF2 mode are compatible
# (Same algorithm, just fixed implementation)

# Old hash (v3.3):
salt123:hash456

# Works with v4.2:
./prth verify "password" "salt123:hash456" 384 2500000
```

This gives you:
- Secure password hashing
- No timing attacks
- Proven primitives
- Unique algorithm design
- Good performance

### PRTHCRYPT
1. **Novel iteration structure** (unique mixing pattern)
2. **Base72 encoding** (custom alphabet/implementation)
3. **Salt integration method** (how salt is woven into state)
4. **Domain separation constants** (specific values)
5. **Multi-round finalization** (finalization strategy)
6. **Specific domain constants** (to prevent cross-protocol attacks)
7. **Zero-wipe** (to clear the sensitive prth_ctx state from RAM after hashing is complete.)

1. **Invite cryptanalysis?** (feel free to post to crypto.stackexchange.com & let me know!)
2. **Run test vectors** (generate standard test cases)
3. **Wait for feedback** (give it 1-2 years)

If no one breaks it in 2 years, I may have done something right.


## Acknowledgments

**Primitives:**
- ChaCha20 by Dan Bernstein
- Inspiration: PBKDF2, bcrypt, Argon2

**Version:** 4.2 
**Status:** Hopefully Production-ready (PBKDF2 mode)  
**Honesty Level:** 100% (Right?)

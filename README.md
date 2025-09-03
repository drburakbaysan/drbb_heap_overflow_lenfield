# drbb_heap_overflow_lenfield

> **Disclaimer**  
> This repository contains **intentionally vulnerable code** and must only be used in **controlled environments**.  
> It is designed for **cybersecurity training and research**, including:  
> - Security Operations Center (**SOC**) training  
> - **Blue Team** exercises (defense, detection, monitoring)  
> - **Red Team** exercises (offensive simulation, exploitation demos)  
> - Academic teaching and **cybersecurity research**  
> - Capture The Flag (**CTF**) challenges or workshops  

---

## 📌 Overview

This repository provides a C program (`drbb_heap_overflow_lenfield.c`) that implementation a **heap-based buffer overflow vulnerability** caused by improper validation of a user-controlled **LEN field**.  
It helps security teams and researchers study both insecure and secure approaches.  

- **Vulnerability class:** Heap Buffer Overflow / Improper Input Validation  
- **Core concept:** The program accepts input formatted as `LEN:<n>;DATA:<string>`.  
  - Memory is allocated according to `LEN`.  
  - However, the actual length of `DATA` may exceed this allocation, causing an **overflow**.  

---

## 📂 Repository Structure

```
.
├── drbb_heap_overflow_lenfield.c   # Vulnerable C source code
└── README.md                       # Documentation
```

---

## ⚙️ Compilation

Using GCC with common warnings:

```bash
gcc -std=c11 -Wall -Wextra -O2   drbb_heap_overflow_lenfield.c   -o drbb_heap_overflow_lenfield
```

With sanitizers for debugging:

```bash
gcc -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer   drbb_heap_overflow_lenfield.c   -o drbb_heap_overflow_lenfield_asan
```

---

## ▶️ Execution

```bash
./drbb_heap_overflow_lenfield "LEN:5;DATA:HELLO"
```

---

## 📥 Input Format

The input must follow this structure:

```
"LEN:<positive_integer>;DATA:<printable_ASCII_string>"
```

✅ Valid examples:  
- `LEN:5;DATA:HELLO`  
- `LEN:10;DATA:0123456789`  
- `LEN:0;DATA:`  

❌ Invalid examples:  
- `LEN:-1;DATA:AAAA`  
- `LEN:10;DATA:\x90\x90`  
- `DATA:HELLO;LEN:5`  

---

## 🧪 Demo Scenarios

### 1. Normal case (no overflow)
```bash
./drbb_heap_overflow_lenfield "LEN:5;DATA:HELLO"
```
Output:
```
[OUTPUT] Parsed record (5 bytes): HELLO
```

---

### 2. Overflow case (vulnerable behavior)
```bash
./drbb_heap_overflow_lenfield "LEN:8;DATA:AAAAAAAAAAAAAAAA"
```
- Allocated buffer: 8 bytes  
- Data length: 16 bytes  
- **Heap overflow occurs**  

---

### 3. With AddressSanitizer
```bash
./drbb_heap_overflow_lenfield_asan "LEN:8;DATA:AAAAAAAAAAAAAAAA"
```
Produces a **heap-buffer-overflow** report, making the vulnerability visible.  

---

## 🔎 Vulnerability Analysis

### Memory layout
- Heap buffer is allocated via:
  ```c
  char *buf = (char*)calloc(len + 1, 1);
  ```
- If `data_len > len`, `memcpy` writes beyond the allocated region.  

### Root cause
Unchecked copy operation:
```c
memcpy(buf, data, data_len);   // ❌ vulnerable
buf[len] = '\0';
```

### Impact
- Program crash (denial of service)  
- Memory corruption  
- Potential code execution under unsafe conditions  

---

## 🛡️ Secure Coding Recommendations

1. Enforce strict parsing (`LEN` must be numeric).  
2. Verify `strlen(DATA) <= LEN`.  
3. Apply a reasonable upper bound in real-world systems.  
4. Safe copy pattern:
   ```c
   size_t copy_len = (data_len < len) ? data_len : len;
   memcpy(buf, data, copy_len);
   buf[copy_len] = '\0';
   ```
5. Reject non-printable input when appropriate.  
6. Fail fast on invalid input.  

---

## 🛠️ Compiler Hardening

Recommended flags:  
- `-Wall -Wextra -Werror`  
- `-D_FORTIFY_SOURCE=2`  
- `-fstack-protector-strong`  
- `-fPIE -pie`  

With sanitizers:  
```bash
gcc -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer   drbb_heap_overflow_lenfield.c   -o drbb_heap_overflow_lenfield_asan
```

---

## ❓ FAQ

**Q: Who should use this repository?**  
A: SOC analysts, Blue Teams, Red Teams, academic researchers, and CTF participants.  

**Q: Can this be used in production?**  
A: Absolutely not. This code is intentionally vulnerable.  

---

## 📜 License

MIT License.

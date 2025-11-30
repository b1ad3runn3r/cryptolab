# Build
```
mkdir build
cd build
cmake ..
cmake --build .
```

# Run

## Generator
```
./generator -m sha1 -p <password> > test_sha1
./generator -m md5 -p <password> > test_md5
```

# Cracker
```
./crack --mask <mask> <path>
```

To test the stuff on a test case, run (full brute)
```
./crack --mask aaaaaa ../test_orig
```

Easier brute
```
./crack --mask dldldu ../test_orig
```


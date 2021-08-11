# TPM Core

## Depends on [Yubico PIV Tool](https://github.com/Yubico/yubico-piv-tool)

## Compiling the library

```console
gcc uniris-yubikey.c -o uniris-yubikey -lykpiv -c
```

## Testing with a driver

```console
gcc driver.c -o driver uniris-yubikey -lykpiv
sudo ./driver
```

## One step driver compilation

```console
gcc driver.c -o driver uniris-yubikey.c -lykpiv
sudo ./driver
```

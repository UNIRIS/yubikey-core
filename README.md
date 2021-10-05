# Yubikey Core

## Depends on [Yubico PIV Tool](https://github.com/Yubico/yubico-piv-tool)

## Compiling the library

```console
gcc uniris-yubikey.c -o uniris-yubikey -lykpiv -lcrypto -c
```

## Testing with a driver

```console
gcc driver.c -o driver uniris-yubikey -lykpiv -lcrypto
./driver
```

## One step driver compilation

```console
gcc driver.c -o driver uniris-yubikey.c -lykpiv -lcrypto
./driver
```

## Compiling Yubikey-core for Elixir support

Make sure that Erlang and Elixir are already installed on the system.

```console
gcc support.c -o support stdio_helpers.c uniris-yubikey.c -lykpiv -lcrypto
```

## Required commands at the start of a new session

```console
sudo iex yubikey-lib.ex
YubiKeyAE.start_link
YubiKeyAE.initialize_yk
```

## Library Functions for Elixir support

```console
YubiKeyAE.get_archethic_index
YubiKeyAE.increment_index
YubiKeyAE.get_root_key
YubiKeyAE.get_current_key
YubiKeyAE.get_next_key
YubiKeyAE.get_past_key(KEY_INDEX)
YubiKeyAE.get_root_certificate
YubiKeyAE.get_current_certificate
YubiKeyAE.get_next_certificate
YubiKeyAE.get_past_certificate(KEY_INDEX)
YubiKeyAE.sign_current_key(HASH_SHA256)
YubiKeyAE.sign_past_key(KEY_INDEX, HASH_SHA256)
YubiKeyAE.ecdh_current_key(RAW_PUBLIC_KEY)
YubiKeyAE.ecdh_past_key(KEY_INDEX, RAW_PUBLIC_KEY)
```

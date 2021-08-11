# Testing

Open elixir terminal

```console
iex
{eph_pub, eph_pv} = :crypto.generate_key(:ecdh, :secp256r1)
eph_pub |> IO.inspect(limit: :infinity) 
```

Change the value of public key in test_key in ecdh.c with the above value of eph_pub.
Replace the below given value of yubikey_pubkey with the public key of yubikey.

```console
yubikey_pubkey = "04600FEC347CADF0AE32A601A9AA5E84F97ECD272A0F7883D66F20F7352B71127C4555F73E92638518236F02CCC89A304263D4832EF125CD33E83CD65FE030F111"
{:ok, yubikey} = Base.decode16(yubikey_pubkey) 
ecdh=:crypto.compute_key(:ecdh, yubikey, eph_pv, :secp256r1)
Base.encode16(ecdh)
```

Recompile ecdh.c in a new terminal and compare the results:

```console
gcc ecdh.c -lcrypto -lykpiv -o ecdh
./ecdh
```

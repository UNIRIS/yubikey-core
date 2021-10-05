Mix.install([
  {:benchee, "~> 1.0", only: :dev}
])

Code.require_file("./yubikey-lib.ex")

YubiKeyAE.start_link()
YubiKeyAE.initialize_yk()

Benchee.run(%{
  "sign with current" => fn data ->
    YubiKeyAE.sign_current_key(data)
  end,
  "sign with past" => fn data ->
    YubiKeyAE.sign_past_key(0, data)
  end
}, inputs: %{
  "with hash of 256bits" => :crypto.strong_rand_bytes(32)
})

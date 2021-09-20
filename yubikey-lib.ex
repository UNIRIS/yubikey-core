defmodule YubiKeyAE do
  @moduledoc false
  use GenServer

  require Logger

  # Client calls
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def initialize_yk() do
    GenServer.call(__MODULE__, {:initialize_yk})
  end

  def get_archethic_index() do
    {:ok, <<index::16>>} = GenServer.call(__MODULE__, {:get_archethic_index})
    index
  end

  def increment_index() do
    GenServer.call(__MODULE__, {:increment_index})
  end

  def get_root_key() do
    {:ok, <<key::binary>>} = GenServer.call(__MODULE__, {:get_root_key})
    # key = Base.encode16(key)
    key
  end

  def get_current_key() do
    {:ok, <<key::binary>>} = GenServer.call(__MODULE__, {:get_current_key})
    # key = Base.encode16(key)
    key
  end

  def get_next_key() do
    {:ok, <<key::binary>>} = GenServer.call(__MODULE__, {:get_next_key})
    # key = Base.encode16(key)
    key
  end

  def get_past_key(index) do
    {:ok, <<key::binary>>} = GenServer.call(__MODULE__, {:get_past_key, index})
    # key = Base.encode16(key)
    key
  end

  def get_root_certificate() do
    {:ok, <<asn_certificate::binary>>} = GenServer.call(__MODULE__, {:get_root_certificate})
    # asn_certificate = Base.encode16(asn_certificate)
    asn_certificate
  end

  def get_current_certificate() do
    {:ok, <<asn_certificate::binary>>} = GenServer.call(__MODULE__, {:get_current_certificate})
    # asn_certificate = Base.encode16(asn_certificate)
    asn_certificate
  end

  def get_next_certificate() do
    {:ok, <<asn_certificate::binary>>} = GenServer.call(__MODULE__, {:get_next_certificate})
    # asn_certificate = Base.encode16(asn_certificate)
    asn_certificate
  end

  def get_past_certificate(index) do
    {:ok, <<asn_certificate::binary>>} = GenServer.call(__MODULE__, {:get_past_certificate, index})
    # asn_certificate = Base.encode16(asn_certificate)
    asn_certificate
  end

  def sign_current_key(<<hash::binary-size(32)>>) do
    {:ok, <<sign::binary>>} = GenServer.call(__MODULE__, {:sign_current_key, hash})
    # sign = Base.encode16(sign)
    sign
  end

  def sign_past_key(index, <<hash::binary-size(32)>>) do
    {:ok, <<sign::binary>>} = GenServer.call(__MODULE__, {:sign_past_key, index, hash})
    # sign = Base.encode16(sign)
    sign
  end

  def ecdh_current_key(<<key::binary-size(65)>>) do
    {:ok, <<ecdh_point::binary-size(32)>>} = GenServer.call(__MODULE__, {:ecdh_current_key, key})
    # ecdh_point = Base.encode16(ecdh_point)
    ecdh_point
  end

  def ecdh_past_key(index, <<key::binary-size(65)>>) do
    {:ok, <<ecdh_point::binary-size(32)>>} = GenServer.call(__MODULE__, {:ecdh_past_key, index, key})
    # ecdh_point = Base.encode16(ecdh_point)
    ecdh_point
  end

  # Server calls
  def init(_opts) do
    support_yk = "./support"

    port =
      Port.open({:spawn_executable, support_yk}, [
        :binary,
        :exit_status,
        {:packet, 4}
      ])

    {:ok, %{port: port, next_id: 1, awaiting: %{}}}
  end

  def handle_call({:initialize_yk}, from, state) do
    {id, state} = send_request(state, 1)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_archethic_index}, from, state) do
    {id, state} = send_request(state, 2)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:increment_index}, from, state) do
    {id, state} = send_request(state, 3)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_root_key}, from, state) do
    {id, state} = send_request(state, 4)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_current_key}, from, state) do
    {id, state} = send_request(state, 5)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_next_key}, from, state) do
    {id, state} = send_request(state, 6)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_past_key, index}, from, state) do
    {id, state} = send_request(state, 7, <<index::16>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_root_certificate}, from, state) do
    {id, state} = send_request(state, 8)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_current_certificate}, from, state) do
    {id, state} = send_request(state, 9)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_next_certificate}, from, state) do
    {id, state} = send_request(state, 10)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_past_certificate, index}, from, state) do
    {id, state} = send_request(state, 11, <<index::16>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:sign_current_key, hash}, from, state) do
    {id, state} = send_request(state, 12, <<hash::binary>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:sign_past_key, index, hash}, from, state) do
    {id, state} = send_request(state, 13, <<index::16, hash::binary>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:ecdh_current_key, key}, from, state) do
    {id, state} = send_request(state, 14, <<key::binary>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:ecdh_past_key, index, key}, from, state) do
    {id, state} = send_request(state, 15, <<index::16, key::binary>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_info({_port, {:data, <<req_id::32, response::binary>>} = _data}, state) do
    case state.awaiting[req_id] do
      nil ->
        {:noreply, state}

      caller ->
        case response do
          <<0::8, error_message::binary>> ->
            reason = String.to_atom(String.replace(error_message, " ", "_"))
            GenServer.reply(caller, {:error, reason})

          <<1::8>> ->
            GenServer.reply(caller, :ok)

          <<1::8, data::binary>> ->
            GenServer.reply(caller, {:ok, data})
        end

        {:noreply, %{state | awaiting: Map.delete(state.awaiting, req_id)}}
    end
  end

  def handle_info({_port, {:exit_status, status}}, _state) do
    :erlang.error({:port_exit, status})
  end

  defp send_request(state, request_type, data) do
    id = state.next_id
    Port.command(state.port, <<id::32>> <> <<request_type>> <> data)
    {id, %{state | next_id: id + 1}}
  end

  defp send_request(state, request_type) do
    id = state.next_id
    Port.command(state.port, <<id::32, request_type::8>>)
    {id, %{state | next_id: id + 1}}
  end
end

# Generate random ecdsa keypair
# {eph_pub, eph_pv} = :crypto.generate_key(:ecdh, :secp256r1)
# eph_pub |> IO.inspect(limit: :infinity)

# reload the code
# r YubiKeyAE

# Verify
# :crypto.verify(:ecdsa, :sha256, :crypto.hash(:sha256,  data), sig, [ pub, :secp256r1 ])
# :crypto.verify(:ecdsa, :sha256, data, sig, [ pub, :secp256r1 ])

# UNIRIS
# <<0x54, 0xc1, 0xa8, 0x30, 0xfa, 0xfd, 0x24, 0xd5, 0xe8, 0xec, 0xe4, 0x32, 0xbd, 0x6e, 0x67, 0xd8, 0xa0, 0xe6, 0x93, 0x05, 0x3b, 0x9f, 0x0d, 0x3b, 0xed, 0x16, 0xc9, 0x10, 0xb6, 0x2c, 0xb8, 0xe9>>
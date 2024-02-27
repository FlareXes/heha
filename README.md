# Change TTL Value

> **Note:** Filenames are case-sensitive

**Step 1:** Save `hello.c` and `Makefile` from `ttl` folder.

**Step 2:** Run Below Commands, Where `hello.c` and `Makefile` are saved.

```bash
make
```

Insert Kernel Module

```bash
sudo insmod hello.ko
```

You should see `Registering filters`

```bash
sudo dmesg
```

**Step 3:** Ping domain like `google.com` and you should see ttl value set to 80.

```bash
ping google.com
```

**Step 4:** Remove Kernel Module.

```bash
sudo rmmode hello.ko
```

# Firewall: Block Port 53 or DNS

> **Note:** Filenames are case-sensitive

**Step 1:** Save `hello.c` and `Makefile` from `firewall` folder.

**Step 2:** Run Below Commands, Where `hello.c` and `Makefile` are saved.

```bash
make
```

Insert Kernel Module

```bash
sudo insmod hello.ko
```

You should see `Registering filters` and `Blocking UDP traffic on port 53`

```bash
sudo dmesg
```

**Step 3:** Ping domain like `google.com` and it **should not work**. Sometimes It only works after step **Step 4**.

```bash
ping google.com
```

**Step 4:** Remove Kernel Module.

```bash
sudo rmmod hello.ko
```

# Capture TCP, UDP, & ICMP Packets

**Step 1:** Save `tcp_udp_icmp.c` from `packet-capture` folder.

**Step 2:** Run Below Commands.

```bash
gcc tcp_udp_icmp.c
```

**Step 3:** Run Compiled Code And You Should See Packets Showing On Screen.

```bash
./a.out
```

# ARP Spoofing

**Step 1:** Save `arp_spoof.py` from `arp-spoof` folder.

**Step 2:** In Last Line Set `target_ip` and `spoof_ip`.

target_ip = IP Address Of Machine Of Target.
spoof_ip = IP Address Of Machine You Wanna Show Fake Address For.

**Step 3:** Run Python Code.

```bash
python arp_spoof.py
```

**Step 4:** Ping All IP Addresses Used In This Task Like `target_ip` and `spoof_ip`.

```bash
ping target_ip
```

```bash
ping spoof_ip
```

**Step 5:** Open New Terminal And Run `arp` command.

```bash
arp
```

or

```bash
arp -n
```

or

```bash
arp -a
```

**Step 6:** Now You Should See Two IP Addresses Having Same MAC Address.

# DNS Client-Server

**Step 1:** Save `dns_server.py` and `dns_client.py` from `dns/client-server` folder.

**Step 2:** Open Two Terminals. 

First Run:

```bash
python dns_server.py
```

Second Run:

```bash
python dns_client.py
```

**Step 3:** Now Enter Any Domain Like `google.com` You Will Always Receive Same Info Provided In `dns_server.py`.

# *Note:* Everything Folder Include Every Code We Did In Lab or Class.

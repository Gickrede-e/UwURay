## About

UwuRay is a fork of [Xray-core](https://github.com/XTLS/Xray-core) with a few custom changes not merged upstream.

## Fork features

- Extended BitTorrent sniffer
- Improved HTTP sniffing
- Stable outbound selection by account email with the `userHash` balancer strategy
- Switched .dat files from `Loyalsoldier/v2ray-rules-dat` to `MetaCubeX/meta-rules-dat`
- REALITY min client version check removed
- Added a workflow to build Linux binaries for releases

### Encrypted BitTorrent

Besides plain signatures, sniffing reports encrypted BitTorrent, matched by a `"protocol": ["bittorrent"]` rule:

- `bittorrent-cache`: TCP of unknown content to a peer the same user talked BitTorrent to in the last 10 minutes.
- `bittorrent-mse`: MSE/PE shaped TCP to a bare IP on a non-well-known port, from a user caught with strong BitTorrent evidence in the last hour. While marked, that user's other encrypted TCP to such destinations (Shadowsocks, obfs4, MTProto proxies) is matched too.

Users are told apart by email (client IP for inbounds without one). Accounts carrying other people's traffic are never marked:

- the bridge account, email `bridge_user`;
- keys online from more than 8 IPs count as shared and are exempt from `bittorrent-mse`; this needs `"statsUserOnline": true` in the policy.

### User-hashed outbound selection

`userHash` maps each authenticated account's raw, case-sensitive `email` to an outbound in a sorted tag pool. Give each account a unique, nonempty email. Different emails can share an exit; duplicate emails share the same assignment. Selection stays stable across connections and restarts with the same email and pool. Adding, removing, or renaming pool tags can redistribute users.

Merge this routing fragment into your configuration, placing its TCP/UDP rule after existing rules that must take priority:

```json
{
  "routing": {
    "balancers": [
      {
        "tag": "client-exits",
        "selector": ["exit-"],
        "strategy": { "type": "userHash" }
      }
    ],
    "rules": [
      { "network": "tcp,udp", "balancerTag": "client-exits" }
    ]
  }
}
```

Each selected outbound must already have a stable public egress IP. There is no health-based failover: an unavailable chosen exit stays selected. Missing email or an empty pool uses the configured `fallbackTag`, or the default outbound when none is configured. Explicit balancer overrides take precedence.

## Usage with [Remnanode](https://github.com/remnawave/node)

Set `CUSTOM_CORE_URL` in Remnanode:

- **x86-64:**
```env
CUSTOM_CORE_URL=https://github.com/MakostaDev/UwuRay/releases/latest/download/Xray-linux-64
```
- **ARM64 (aarch64):**
```env
CUSTOM_CORE_URL=https://github.com/MakostaDev/UwuRay/releases/latest/download/Xray-linux-arm64-v8a
```

Then restart the container:
```bash
docker compose down remnanode && docker compose up -d remnanode && docker compose logs -f remnanode
```

## Donation

- **TRX(Tron)/USDT: `TGJetncBrGCQmkwpz9hfWDX5wv89ia6WqY`**
- **TON(GRAM)/USDT: `UQA5x7v29RmYeBRIn_7ifX9Tk1HavjZJduiH8-oPe7tC6B4L`**
- **BTC: `bc1q0am0h4l9arx3agcfntnkjm399t62vc9f8x0f0a`**
- **SOL/USDT/USDC: `865FJALSh6rUxQAFyVAd3A6nfp22ZhwzZugG71q6phgL`**
- **ETH/USDT/USDC: `0x34cEC6fCE7F607D24191F606c23DDB72A3857BFc`**

## Recommended tools

[![Remnawave](https://github.com/user-attachments/assets/a22d34ae-01ee-441c-843a-85356748ed1e)](https://docs.rw)

## License

[Mozilla Public License Version 2.0](https://github.com/MakostaDev/UwuRay/blob/main/LICENSE)

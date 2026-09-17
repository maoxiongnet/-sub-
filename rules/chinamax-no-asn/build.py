#!/usr/bin/env python3
"""生成不含 IP-ASN 的 ChinaMax 规则集（只用 Python 标准库）。

blackmatrix7 ChinaMax 的规则原值、原顺序保留；其中 `IP-ASN,132203`（腾讯）在原位置换成
MetaCubeX 从 GeoLite2-ASN 导出的网段，其他 IP-ASN / SRC-IP-ASN 规则删除。这样客户端不再需要
下载 ASN 数据库。

任一来源下载失败或格式校验不通过，都以非零退出码结束、不改动已有输出文件（已发布的上一版继续可用）。
校验规则与 py-web1 分支 fix/subscription-rules-without-asn 的 FilteredRuleSetService 保持一致。
"""

import argparse
import hashlib
import ipaddress
import re
import sys
import time
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
    "master/rule/Clash/ChinaMax/ChinaMax.list"
)
ASN_SOURCE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/asn/AS132203.list"
TENCENT_ASN = "132203"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_ASN_BYTES = 512 * 1024
MAX_ASN_ROWS = 4096
RULE_TYPES = frozenset({
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "PROCESS-NAME",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "SRC-IP-ASN",
})
IP_RULE_TYPES = frozenset({"IP-CIDR", "IP-CIDR6", "IP-ASN", "SRC-IP-ASN"})


class BuildError(Exception):
    pass


def download(url: str, limit: int) -> bytes:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "chinamax-no-asn-builder"})
            with urllib.request.urlopen(request, timeout=30) as response:
                # 只认固定上游本身，不接受跳转到别处的内容。
                if response.geturl() != url:
                    raise BuildError(f"来源发生跳转：{url} -> {response.geturl()}")
                body = response.read(limit + 1)
        except OSError as error:  # URLError / HTTPError / 超时都是 OSError
            last_error = error
            time.sleep(5 * (attempt + 1))
            continue
        if len(body) > limit:
            raise BuildError(f"来源超过大小上限（{limit} 字节）：{url}")
        return body
    raise BuildError(f"下载失败：{url}：{last_error}")


def read_file(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        body = source.read(limit + 1)
    if len(body) > limit:
        raise BuildError(f"文件超过大小上限（{limit} 字节）：{path}")
    return body


def parse_tencent_cidrs(raw: bytes) -> list[str]:
    rows = [
        line.strip()
        for line in raw.decode("utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not rows or len(rows) > MAX_ASN_ROWS:
        raise BuildError("腾讯网段条数异常")
    try:
        networks = [ipaddress.ip_network(row, strict=True) for row in rows]
    except ValueError as error:
        raise BuildError(f"腾讯网段格式错误：{error}") from error
    if any(not network.is_global or network.prefixlen == 0 for network in networks):
        raise BuildError("腾讯网段出现非公网或全网范围")
    if len(set(networks)) != len(networks):
        raise BuildError("腾讯网段出现重复")
    return [f"{'IP-CIDR6' if net.version == 6 else 'IP-CIDR'},{net}" for net in networks]


def filter_chinamax(raw: bytes, tencent_rules: list[str]) -> tuple[list[str], dict[str, int]]:
    text = raw.decode("utf-8-sig")
    declared_total = re.search(r"(?m)^# TOTAL:\s*(\d+)\s*$", text)
    if declared_total is None:
        raise BuildError("ChinaMax 缺少 TOTAL 行，无法确认下载完整")
    retained: list[str] = []
    total = removed = expanded = 0
    for original_line in text.splitlines():
        line = original_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        kind = parts[0]
        if kind not in RULE_TYPES or len(parts) not in {2, 3} or not parts[1]:
            raise BuildError(f"ChinaMax 出现未验证的规则格式：{line[:120]}")
        if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in line):
            raise BuildError("ChinaMax 规则包含控制字符")
        if len(parts) == 3 and (kind not in IP_RULE_TYPES or parts[2] != "no-resolve"):
            raise BuildError(f"ChinaMax 规则参数发生变化：{line[:120]}")
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            try:
                network = ipaddress.ip_network(parts[1], strict=False)
            except ValueError as error:
                raise BuildError(f"ChinaMax 网段格式错误：{line[:120]}") from error
            if kind == "IP-CIDR6" and network.version != 6:
                raise BuildError(f"ChinaMax IPv6 规则格式错误：{line[:120]}")
        total += 1
        if kind in {"IP-ASN", "SRC-IP-ASN"}:
            if not parts[1].isascii() or not parts[1].isdecimal():
                raise BuildError(f"ChinaMax ASN 格式错误：{line[:120]}")
            removed += 1
            # 只补回已核实的腾讯 ASN，保持原位置与 no-resolve；其他 ASN 不猜测补全。
            if kind == "IP-ASN" and parts[1] == TENCENT_ASN:
                suffix = ",no-resolve" if len(parts) == 3 else ""
                retained.extend(f"{rule}{suffix}" for rule in tencent_rules)
                expanded += len(tencent_rules)
        else:
            retained.append(line)
    if total != int(declared_total[1]) or not retained:
        raise BuildError(f"ChinaMax 条数不完整（TOTAL {declared_total[1]}，实际 {total}）")
    return retained, {"source_rules": total, "removed_asn": removed, "tencent_cidrs": expanded}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True, help="输出文件路径")
    parser.add_argument("--source-file", type=Path, help="使用本地 ChinaMax.list，默认从上游下载")
    parser.add_argument("--asn-source-file", type=Path, help="使用本地腾讯网段文件，默认从上游下载")
    args = parser.parse_args()

    try:
        raw = (read_file(args.source_file, MAX_SOURCE_BYTES) if args.source_file
               else download(SOURCE_URL, MAX_SOURCE_BYTES))
        asn_raw = (read_file(args.asn_source_file, MAX_ASN_BYTES) if args.asn_source_file
                   else download(ASN_SOURCE_URL, MAX_ASN_BYTES))
        rules, stats = filter_chinamax(raw, parse_tencent_cidrs(asn_raw))
    except BuildError as error:
        print(f"生成失败，保留原文件：{error}", file=sys.stderr)
        return 1

    body = "\n".join(rules) + "\n"
    header = "\n".join([
        "# NAME: ChinaMax（无 IP-ASN）",
        f"# SOURCE: {SOURCE_URL}",
        f"# SOURCE-SHA256: {hashlib.sha256(raw).hexdigest()}",
        f"# TENCENT-CIDR: {ASN_SOURCE_URL}",
        f"# TENCENT-CIDR-SHA256: {hashlib.sha256(asn_raw).hexdigest()}",
        f"# CHANGE: IP-ASN,{TENCENT_ASN} 换成 {stats['tencent_cidrs']} 条网段，共删除 {stats['removed_asn']} 条 ASN 规则",
        f"# TOTAL: {len(rules)}",
        "# LICENSE: GPL-2.0（blackmatrix7/ios_rule_script）、GPL-3.0（MetaCubeX/meta-rules-dat）",
    ]) + "\n"

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_bytes((header + body).encode("utf-8"))
    temporary.replace(args.output)

    print(f"来源规则 {stats['source_rules']} 条，删除 ASN {stats['removed_asn']} 条，"
          f"补入腾讯网段 {stats['tencent_cidrs']} 条，输出 {len(rules)} 条")
    print(f"规则正文 SHA-256：{hashlib.sha256(body.encode('utf-8')).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

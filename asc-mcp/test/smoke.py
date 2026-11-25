#!/usr/bin/env python3
"""冒烟测试：用官方 MCP 客户端起 server.py（stdio），列工具并真调一次。

    /opt/asc-mcp/venv/bin/python test/smoke.py [apk路径]

不给 APK 就跑"只列工具 + 不存在路径的错误路径"两项。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

SERVER = Path(__file__).resolve().parent.parent / "server.py"
PYTHON = "/opt/asc-mcp/venv/bin/python"


async def main() -> int:
    params = StdioServerParameters(command=PYTHON, args=[str(SERVER)])
    failures = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            info = await session.initialize()
            print(f"✓ 握手：{info.server_info.name} {info.server_info.version} / {info.protocol_version}")

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            expected = {
                "apk_info",
                "apk_manifest",
                "apk_list_classes",
                "apk_decompile_class",
                "apk_disassemble_class",
                "apk_find_refs",
                "apk_strings",
                "apk_smali_grep",
            }
            if expected == set(names):
                print(f"✓ 工具清单：{', '.join(names)}")
            else:
                failures += 1
                print(f"✗ 工具清单不符合预期：{names}")

            bad = await session.call_tool("apk_info", {"apk": "/nonexistent/none.apk"})
            text = bad.content[0].text if bad.content else ""
            if "APK 不存在" in text:
                print("✓ 错误路径：返回可读原因")
            else:
                failures += 1
                print(f"✗ 错误路径未带原因：{text[:120]!r}")

            if len(sys.argv) > 1:
                apk = sys.argv[1]
                res = await session.call_tool("apk_info", {"apk": apk})
                text = res.content[0].text if res.content else ""
                ok = not res.is_error and "package:" in text
                print(("✓" if ok else "✗") + " apk_info:")
                print("   " + text.replace("\n", "\n   ")[:400])
                failures += 0 if ok else 1

                listing = await session.call_tool(
                    "apk_list_classes", {"apk": apk, "limit": 3}
                )
                ltext = listing.content[0].text if listing.content else ""
                ok = "共" in ltext and "dex" not in ltext[:20]
                print(("✓" if ok else "✗") + " apk_list_classes 分页:", ltext.splitlines()[0])
                failures += 0 if ok else 1

                strings = await session.call_tool(
                    "apk_strings",
                    {"apk": apk, "pattern": "msfwifi.3g.qq.com", "sources": "dex", "limit": 3},
                )
                stext = strings.content[0].text if strings.content else ""
                ok = "命中" in stext and "[dex]" in stext
                print(("✓" if ok else "✗") + " apk_strings:", stext.splitlines()[-1][:120])
                failures += 0 if ok else 1

                smali = await session.call_tool(
                    "apk_smali_grep",
                    {
                        "apk": apk,
                        "pattern": "invoke-static {v0}, Ljava/lang/",
                        "class_prefix": "Lcom/tencent/mobileqq/utils/",
                        "max_classes": 20,
                        "limit": 5,
                    },
                )
                mtext = smali.content[0].text if smali.content else ""
                ok = "命中" in mtext
                print(("✓" if ok else "✗") + " apk_smali_grep:", mtext.splitlines()[1][:120])
                failures += 0 if ok else 1

    print("\n结论：" + ("全部通过" if failures == 0 else f"{failures} 项失败"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

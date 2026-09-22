#!/usr/bin/env python
"""打开最近一次解压出来的内容（图片优先用看图软件）。

配合桌面快捷方式使用：不想重新处理，只想看上次解压了什么。
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from app import recent


def main() -> int:
    msg = recent.open_latest()
    print(msg)
    print()
    # 双击运行时留窗口，方便看到结果
    try:
        input("按回车关闭...")
    except EOFError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

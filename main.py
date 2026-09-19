"""通用解压归档助手 — 入口。

用法:
    python main.py                      启动图形界面
    python main.py --auto <源目录> ...   批量自动模式
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _run():
    if len(sys.argv) > 1 and sys.argv[1] == "--auto":
        from app.cli import main as cli_main
        sys.exit(cli_main(sys.argv[2:]))
    from app.gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    _run()

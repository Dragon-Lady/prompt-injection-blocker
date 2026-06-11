"""Command-line interface.

Argument parsing is hand-rolled (not argparse) to preserve the exit-code
contract: argparse exits with code 2 on bad arguments, but 2 means "blocking
promptware found" here. Errors must exit 1.
"""

import json
import os
import sys

from .scanner import scan_target

HELP_TEXT = """prompt-injection-blocker

Read-only scanner for prompt-injection and LLM anti-analysis text in files
before agent review.

Usage:
  prompt-injection-blocker [target] [--json] [--report report.json]

Options:
  --json              print JSON report to stdout
  --report <path>     write JSON report to a specific path
  -h, --help          show this help

Exit codes:
  0  no blocking promptware patterns found
  1  usage or runtime error
  2  blocking promptware patterns found
"""


def _parse_args(argv):
    args = {"target": ".", "json": False, "report_path": "", "help": False}

    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--help", "-h"):
            args["help"] = True
        elif arg == "--json":
            args["json"] = True
        elif arg == "--report":
            index += 1
            if index >= len(argv) or not argv[index]:
                raise ValueError("--report requires a file path")
            args["report_path"] = argv[index]
        elif arg.startswith("--report="):
            args["report_path"] = arg[len("--report="):]
            if not args["report_path"]:
                raise ValueError("--report requires a file path")
        elif not arg.startswith("-"):
            args["target"] = arg
        else:
            raise ValueError(f"Unknown argument: {arg}")
        index += 1

    return args


def _print_human(report, written_report_path):
    print("Prompt Injection Blocker")
    print(f"Target: {report['target']}")
    print(f"Risk: {report['risk']}")
    print(f"Scanned: {report['summary']['filesScanned']} files")
    print(f"Findings: {report['summary']['findings']}")
    print("")

    if report["risk"] == "blocked":
        print("STOP")
        print("Prompt-injection or LLM anti-analysis text was found.")
        print("Do not paste the flagged text into an agent. Defang, summarize, or isolate it first.")
        print("")
    else:
        print("No blocking promptware patterns were found by this scanner.")
        print("This does not prove content is safe; it only covers known local rules.")
        print("")

    if report["findings"]:
        print("Findings:")
        for item in report["findings"]:
            print(f"[{item['severity']}] {item['type']}")
            print(f"  {item['path']}")
            print(f"  {item['message']}")
            if item["evidence"]:
                print(f"  evidence: {item['evidence']}")
        print("")

    print("Guidance:")
    for item in report["guidance"]:
        print(f"- {item}")

    if written_report_path:
        print("")
        print(f"JSON report written: {written_report_path}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    try:
        args = _parse_args(argv)
        if args["help"]:
            print(HELP_TEXT)
            return 0

        report = scan_target(args["target"])
        written_report_path = ""
        if args["report_path"]:
            written_report_path = os.path.abspath(args["report_path"])
            with open(written_report_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(report, indent=2) + "\n")

        if args["json"]:
            print(json.dumps(report, indent=2))
        else:
            _print_human(report, written_report_path)

        return 2 if report["risk"] == "blocked" else 0
    except (ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""
Check every static AWS CDK remediation snippet end to end.

For each KSI in the CDK library this script:
  1. wraps the snippet in a Stack (imports hoisted, body in the constructor),
  2. type-checks it with ``tsc --strict`` against real aws-cdk-lib,
  3. runs ``cdk synth`` (via the App API) to produce a CloudFormation template,
  4. scans that template with FedRAMP-Auto's own parser + static rules and
     confirms the KSI the snippet is meant to fix is now satisfied.

Requires Node.js 18+ and npm; downloads aws-cdk-lib, constructs and
typescript into a temporary directory (nothing is installed globally).

Usage
-----
    poetry run python scripts/check_cdk_snippets.py [--workdir DIR] [--cdk-version 2.x.y]

Exit code 0 when every snippet passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fedramp_auto.advisor.remediation import _STATIC_REMEDIATIONS_CDK  # noqa: E402
from fedramp_auto.gaps.detector import _KSI_CATALOGUE  # noqa: E402
from fedramp_auto.mapper.control_mapper import ControlMapper  # noqa: E402
from fedramp_auto.parser.cloudformation import parse_file  # noqa: E402

_TSCONFIG = {
    "compilerOptions": {
        "target": "ES2022",
        "module": "commonjs",
        "strict": True,
        "noUnusedLocals": False,
        "skipLibCheck": True,
        "outDir": "dist",
        "rootDir": "src",
    },
    "include": ["src"],
}


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    exe = shutil.which(cmd[0])
    if exe is None:
        sys.exit(f"error: {cmd[0]} not found on PATH (Node.js 18+ is required)")
    return subprocess.run(
        [exe, *cmd[1:]], cwd=cwd, capture_output=True, text=True, encoding="utf-8"
    )


def _stack_class(ksi_id: str) -> str:
    return "Snippet" + ksi_id.replace("KSI-", "").replace("-", "")


def _wrap(ksi_id: str, snippet: str) -> str:
    """Hoist imports; put the rest of the snippet inside a Stack constructor."""
    lines = snippet.splitlines()
    imports = [ln for ln in lines if ln.startswith("import ")]
    body = "\n".join(ln for ln in lines if not ln.startswith("import ")).strip()
    return "\n".join([
        *imports,
        "import * as __cdk from 'aws-cdk-lib';",
        "import { Construct as __Construct } from 'constructs';",
        "",
        f"export class {_stack_class(ksi_id)} extends __cdk.Stack {{",
        "  constructor(scope: __Construct, id: string) {",
        "    super(scope, id);",
        textwrap.indent(body, "    "),
        "  }",
        "}",
        "",
    ])


def _write_project(workdir: Path, cdk_version: str) -> None:
    src = workdir / "src"
    src.mkdir(parents=True, exist_ok=True)
    (workdir / "package.json").write_text(json.dumps({
        "name": "fedramp-auto-cdk-snippet-check",
        "private": True,
        "dependencies": {
            "aws-cdk-lib": cdk_version,
            "constructs": "^10.0.0",
            "typescript": "~5.6.0",
        },
    }, indent=2))
    (workdir / "tsconfig.json").write_text(json.dumps(_TSCONFIG, indent=2))

    main = ["import * as cdk from 'aws-cdk-lib';"]
    for ksi_id, entry in _STATIC_REMEDIATIONS_CDK.items():
        module = ksi_id.lower()
        (src / f"{module}.ts").write_text(_wrap(ksi_id, entry["snippet"]), encoding="utf-8")
        main.append(f"import {{ {_stack_class(ksi_id)} }} from './{module}';")
    main.append("const app = new cdk.App({ outdir: 'cdk.out' });")
    for ksi_id in _STATIC_REMEDIATIONS_CDK:
        main.append(f"new {_stack_class(ksi_id)}(app, '{ksi_id}');")
    main.append("app.synth();")
    (src / "main.ts").write_text("\n".join(main) + "\n", encoding="utf-8")


def _check_ksis(workdir: Path) -> list[str]:
    """Scan each synthesized stack; return failures."""
    ksis = {k.ksi_id: k for k in _KSI_CATALOGUE}
    mapper = ControlMapper(llm_fallback=False)
    failures = []
    for ksi_id in _STATIC_REMEDIATIONS_CDK:
        template = workdir / "cdk.out" / f"{ksi_id}.template.json"
        parsed = parse_file(template)
        controls = {c for rm in mapper.map_resources(parsed.resources) for c in rm.control_ids}
        missing = sorted(set(ksis[ksi_id].control_ids) - controls)
        status = "ok" if not missing else f"FAIL - still missing {', '.join(missing)}"
        print(f"  {ksi_id:<10} {len(parsed.resources):>3} resources  {status}")
        if missing:
            failures.append(ksi_id)
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workdir", type=Path, help="Keep the generated CDK project here")
    ap.add_argument("--cdk-version", default="^2.0.0", help="aws-cdk-lib version range")
    args = ap.parse_args()

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="cdk-snippets-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"Project: {workdir}")
    _write_project(workdir, args.cdk_version)

    steps = [
        ("npm install", ["npm", "install", "--no-audit", "--no-fund", "--loglevel=error"]),
        ("tsc --strict", ["npx", "tsc", "-p", "."]),
        ("cdk synth", ["node", "dist/main.js"]),
    ]
    for label, cmd in steps:
        print(f"- {label} ...")
        result = _run(cmd, workdir)
        if result.returncode != 0:
            print(result.stdout + result.stderr)
            print(f"FAILED at {label}")
            return 1

    installed = json.loads(
        (workdir / "node_modules" / "aws-cdk-lib" / "package.json").read_text()
    )["version"]
    print(f"- scan synthesized templates (aws-cdk-lib {installed}) ...")
    failures = _check_ksis(workdir)

    if not args.workdir:
        shutil.rmtree(workdir, ignore_errors=True)
    if failures:
        print(f"FAILED: {len(failures)} snippet(s) do not close their KSI")
        return 1
    print(f"All {len(_STATIC_REMEDIATIONS_CDK)} CDK snippets compile, synth, and close their KSI.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

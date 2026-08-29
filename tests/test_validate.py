from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest

from ru_routing.generate import NativeTools, generate_all
from ru_routing.models import Category, Dataset, RuleEntry, RuleKind
from ru_routing.resolve import ConflictReport, ResolvedBuild
from ru_routing.tooling import CompletedTool, ToolError
from ru_routing.validate import (
    ValidationError,
    ValidationThresholds,
    _mihomo_config,
    _validate_native,
    validate_build,
)


class FakeNativeRunner:
    def __init__(
        self, *, nondeterministic: bool = False, fail_mrs_read: bool = False
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], Path]] = []
        self.compilations = 0
        self.nondeterministic = nondeterministic
        self.fail_mrs_read = fail_mrs_read
        self._lock = threading.Lock()

    def run(self, argv, cwd):
        command = tuple(argv)
        working_directory = Path(cwd)
        with self._lock:
            self.calls.append((command, working_directory))
        if (
            self.fail_mrs_read
            and command[0] == "mihomo-tool"
            and "convert-ruleset" in command
            and command[3] == "mrs"
        ):
            raise ToolError("corrupt MRS")
        output = self._output(command, working_directory)
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            if command[0] == "sing-box-tool" and "decompile" in command:
                content = b'{"version":1,"rules":[]}\n'
            else:
                with self._lock:
                    self.compilations += 1
                    compilations = self.compilations
                suffix = (
                    str(compilations).encode() if self.nondeterministic else b""
                )
                content = b"native-artifact\n" + suffix
            output.write_bytes(content)
        return CompletedTool(command, working_directory, 0, "", "")

    @staticmethod
    def _output(command: tuple[str, ...], cwd: Path) -> Path | None:
        if command[0] == "dlc-tool":
            return Path(_flag(command, "--outputdir")) / _flag(
                command, "--outputname"
            )
        if command[0] == "geoip-tool":
            return cwd / "geoip.dat"
        if command[0] == "sing-box-tool":
            return Path(command[command.index("--output") + 1])
        if command[0] == "mihomo-tool" and "convert-ruleset" in command:
            return Path(command[-1])
        return None


def test_validate_build_rejects_forbidden_default_routes_before_native_checks(
    tmp_path,
):
    runner = FakeNativeRunner()
    unsafe = _build(cidr="0.0.0.0/0")

    with pytest.raises(ValidationError, match=r"lite/ru-ip.*0\.0\.0\.0/0"):
        validate_build(
            unsafe, tmp_path / "dist", ValidationThresholds(), _tools(runner)
        )

    assert runner.calls == []


def test_validate_build_rejects_ipv6_default_route(tmp_path):
    unsafe = _build(cidr="::/0")

    with pytest.raises(ValidationError, match=r"::/0"):
        validate_build(
            unsafe,
            tmp_path / "dist",
            ValidationThresholds(),
            _tools(FakeNativeRunner()),
        )


def test_validate_build_enforces_required_categories_and_minimum_counts(tmp_path):
    runner = FakeNativeRunner()
    build = _build()
    generate_all(build, tmp_path / "dist", _tools(runner))

    with pytest.raises(ValidationError, match="required category lite/spy is absent"):
        validate_build(
            build,
            tmp_path / "dist",
            ValidationThresholds(required_categories={"lite": frozenset({"spy"})}),
            _tools(runner),
        )

    with pytest.raises(
        ValidationError, match="server/blocked has 1 entries; minimum is 2"
    ):
        validate_build(
            build,
            tmp_path / "dist",
            ValidationThresholds(
                minimum_category_entries={("server", "blocked"): 2}
            ),
            _tools(runner),
        )


def test_validate_build_requires_every_artifact_derived_from_the_build(tmp_path):
    runner = FakeNativeRunner()
    build = _build()
    dist = tmp_path / "dist"
    generate_all(build, dist, _tools(runner))
    (dist / "sing-box/lite/blocked.srs").unlink()

    with pytest.raises(
        ValidationError, match="required artifact is absent.*blocked.srs"
    ):
        validate_build(build, dist, ValidationThresholds(), _tools(runner))


def test_validate_build_checks_sha256sums_before_native_tools(tmp_path):
    runner = FakeNativeRunner()
    build = _build()
    dist = tmp_path / "dist"
    generate_all(build, dist, _tools(runner))
    runner.calls.clear()
    (dist / "SHA256SUMS").write_text(
        f"{'0' * 64}  xray/geosite.dat\n", encoding="utf-8"
    )

    with pytest.raises(ValidationError, match="checksum mismatch.*xray/geosite.dat"):
        validate_build(build, dist, ValidationThresholds(), _tools(runner))

    assert runner.calls == []


def test_validate_build_runs_native_load_checks_with_exact_argv(tmp_path):
    runner = FakeNativeRunner()
    build = _build()
    dist = tmp_path / "dist"
    generate_all(build, dist, _tools(runner))
    _write_checksums(dist)
    runner.calls.clear()

    report = validate_build(
        build,
        dist,
        ValidationThresholds(require_checksums=True, check_determinism=False),
        _tools(runner),
    )

    work = tmp_path / ".dist.validate"
    assert runner.calls == [
        (
            ("xray-tool", "run", "-test", "-config", str(work / "xray-lite.json")),
            work,
        ),
        (
            (
                "xray-tool",
                "run",
                "-test",
                "-config",
                str(work / "xray-server.json"),
            ),
            work,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "decompile",
                "--output",
                str(work / "sing-box/lite/blocked.json"),
                str(dist / "sing-box/lite/blocked.srs"),
            ),
            work,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "decompile",
                "--output",
                str(work / "sing-box/lite/ru-ip.json"),
                str(dist / "sing-box/lite/ru-ip.srs"),
            ),
            work,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "decompile",
                "--output",
                str(work / "sing-box/server/blocked.json"),
                str(dist / "sing-box/server/blocked.srs"),
            ),
            work,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "decompile",
                "--output",
                str(work / "sing-box/server/ru-ip.json"),
                str(dist / "sing-box/server/ru-ip.srs"),
            ),
            work,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "domain",
                "mrs",
                str(dist / "mihomo/lite/blocked-domain.mrs"),
                str(work / "mihomo/lite/blocked-domain.txt"),
            ),
            work,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "ipcidr",
                "mrs",
                str(dist / "mihomo/lite/ru-ip-ipcidr.mrs"),
                str(work / "mihomo/lite/ru-ip-ipcidr.txt"),
            ),
            work,
        ),
        (
            (
                "mihomo-tool",
                "-d",
                str(work),
                "-t",
                "-f",
                str(work / "mihomo-lite.yaml"),
            ),
            work,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "domain",
                "mrs",
                str(dist / "mihomo/server/blocked-domain.mrs"),
                str(work / "mihomo/server/blocked-domain.txt"),
            ),
            work,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "ipcidr",
                "mrs",
                str(dist / "mihomo/server/ru-ip-ipcidr.mrs"),
                str(work / "mihomo/server/ru-ip-ipcidr.txt"),
            ),
            work,
        ),
        (
            (
                "mihomo-tool",
                "-d",
                str(work),
                "-t",
                "-f",
                str(work / "mihomo-server.yaml"),
            ),
            work,
        ),
    ]
    assert report.category_counts == {
        ("lite", "blocked"): 1,
        ("lite", "ru-ip"): 1,
        ("server", "blocked"): 1,
        ("server", "ru-ip"): 1,
    }
    assert report.checksum_entries == len(_files_without_checksum(dist))
    assert report.native_checks == 12
    assert report.deterministic is None
    assert not work.exists()


def test_validate_build_rebuilds_and_rejects_nondeterministic_artifacts(tmp_path):
    runner = FakeNativeRunner(nondeterministic=True)
    build = _build()
    dist = tmp_path / "dist"
    generate_all(build, dist, _tools(runner))

    with pytest.raises(ValidationError, match="nondeterministic artifact"):
        validate_build(build, dist, ValidationThresholds(), _tools(runner))


def test_validate_native_rejects_unsafe_category_name(tmp_path):
    runner = FakeNativeRunner()
    unsafe = Category(
        "../evil", frozenset({_entry(RuleKind.DOMAIN, "blocked.example")})
    )
    dataset = Dataset({"../evil": unsafe})
    build = ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))
    dist = tmp_path / "dist"
    dist.mkdir()

    with pytest.raises(ValidationError, match="unsafe category name"):
        _validate_native(build, dist, _tools(runner))


def test_mihomo_config_rejects_unsafe_category_name():
    unsafe = Category(
        "../evil", frozenset({_entry(RuleKind.DOMAIN, "blocked.example")})
    )
    dataset = Dataset({"../evil": unsafe})

    with pytest.raises(ValidationError, match="unsafe category name"):
        _mihomo_config("lite", dataset)


def test_validate_build_reports_mihomo_mrs_decode_failures(tmp_path):
    build_runner = FakeNativeRunner()
    build = _build()
    dist = tmp_path / "dist"
    generate_all(build, dist, _tools(build_runner))

    with pytest.raises(ValidationError, match="Mihomo MRS load.*corrupt MRS"):
        validate_build(
            build,
            dist,
            ValidationThresholds(check_determinism=False),
            _tools(FakeNativeRunner(fail_mrs_read=True)),
        )


def _build(cidr: str = "203.0.113.0/24") -> ResolvedBuild:
    blocked = Category(
        "blocked", frozenset({_entry(RuleKind.DOMAIN, "blocked.example")})
    )
    ru_ip = Category("ru-ip", frozenset({_entry(RuleKind.CIDR, cidr)}))
    dataset = Dataset({"blocked": blocked, "ru-ip": ru_ip})
    return ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))


def _entry(kind: RuleKind, value: str) -> RuleEntry:
    return RuleEntry(kind, value, frozenset({"fixture"}))


def _tools(runner: FakeNativeRunner) -> NativeTools:
    return NativeTools(
        runner=runner,
        dlc="dlc-tool",
        geoip="geoip-tool",
        sing_box="sing-box-tool",
        mihomo="mihomo-tool",
        xray="xray-tool",
    )


def _flag(command: tuple[str, ...], name: str) -> str:
    prefix = f"{name}="
    return next(
        argument.removeprefix(prefix)
        for argument in command
        if argument.startswith(prefix)
    )


def _write_checksums(dist: Path) -> None:
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(dist)}\n"
        for path in sorted(dist.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (dist / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def _files_without_checksum(dist: Path) -> set[str]:
    return {
        str(path.relative_to(dist))
        for path in dist.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }

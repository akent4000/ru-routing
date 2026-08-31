from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path

import pytest

from ru_routing.generate import GenerationError, NativeTools, generate_all
from ru_routing.models import Category, Dataset, RuleEntry, RuleKind
from ru_routing.resolve import ConflictReport, ResolvedBuild
from ru_routing.tooling import CompletedTool, ToolError, ToolRunner
from ru_routing.validate import ValidationError, ValidationThresholds, validate_build


class FakeRunner:
    def __init__(self, *, omit: str | None = None, fail: str | None = None) -> None:
        self.calls: list[tuple[tuple[str, ...], Path]] = []
        self.dlc_sources: dict[Path, dict[str, str]] = {}
        self._lock = threading.Lock()
        self.omit = omit
        self.fail = fail

    def run(self, argv, cwd):
        command = tuple(argv)
        working_directory = Path(cwd)
        with self._lock:
            self.calls.append((command, working_directory))
            if command[0] == "dlc-tool":
                datapath = Path(_flag(command, "--datapath"))
                self.dlc_sources[datapath] = {
                    item.relative_to(datapath).as_posix(): item.read_text()
                    for item in sorted(datapath.rglob("*"))
                    if item.is_file()
                }
        if command[0] == self.fail:
            raise ToolError(f"simulated {self.fail} failure")
        output = self._output(command, working_directory)
        if command[0] != self.omit:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"compiled by {command[0]}\n".encode())
        return CompletedTool(command, working_directory, 0, "ok\n", "")

    @staticmethod
    def _output(command: tuple[str, ...], cwd: Path) -> Path:
        if command[0] == "dlc-tool":
            output_dir = Path(_flag(command, "--outputdir"))
            return output_dir / _flag(command, "--outputname")
        if command[0] == "geoip-tool":
            return cwd / "geoip.dat"
        if command[0] == "sing-box-tool":
            return Path(command[command.index("--output") + 1])
        if command[0] == "mihomo-tool":
            return Path(command[-1])
        raise AssertionError(f"unexpected tool call: {command}")


def test_generate_all_uses_official_argv_and_publishes_complete_tree(tmp_path):
    dist = tmp_path / "dist"
    runner = FakeRunner()
    tools = NativeTools(
        runner=runner,
        dlc="dlc-tool",
        geoip="geoip-tool",
        sing_box="sing-box-tool",
        mihomo="mihomo-tool",
    )

    result = generate_all(build(), dist, tools)

    stage = tmp_path / ".dist.generate"
    inputs = stage / ".compiler-inputs"
    xray = stage / "xray"
    sing_box = stage / "sing-box"
    mihomo = stage / "mihomo"
    assert sorted(runner.calls) == sorted([
        (
            (
                "dlc-tool",
                f"--datapath={inputs / 'xray/lite/geosite'}",
                f"--outputdir={xray}",
                "--outputname=geosite-lite.dat",
            ),
            stage,
        ),
        (("geoip-tool", "-c", str(inputs / "xray/lite/geoip.json")), xray),
        (
            (
                "dlc-tool",
                f"--datapath={inputs / 'xray/server/geosite'}",
                f"--outputdir={xray}",
                "--outputname=geosite.dat",
            ),
            stage,
        ),
        (("geoip-tool", "-c", str(inputs / "xray/server/geoip.json")), xray),
        (
            (
                "sing-box-tool",
                "rule-set",
                "compile",
                "--output",
                str(sing_box / "lite/blocked.srs"),
                str(sing_box / "lite/blocked.json"),
            ),
            stage,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "compile",
                "--output",
                str(sing_box / "lite/ru-ip.srs"),
                str(sing_box / "lite/ru-ip.json"),
            ),
            stage,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "compile",
                "--output",
                str(sing_box / "server/blocked.srs"),
                str(sing_box / "server/blocked.json"),
            ),
            stage,
        ),
        (
            (
                "sing-box-tool",
                "rule-set",
                "compile",
                "--output",
                str(sing_box / "server/ru-ip.srs"),
                str(sing_box / "server/ru-ip.json"),
            ),
            stage,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "domain",
                "yaml",
                str(inputs / "mihomo/lite/blocked-domain.yaml"),
                str(mihomo / "lite/blocked-domain.mrs"),
            ),
            stage,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "ipcidr",
                "yaml",
                str(inputs / "mihomo/lite/ru-ip-ipcidr.yaml"),
                str(mihomo / "lite/ru-ip-ipcidr.mrs"),
            ),
            stage,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "domain",
                "yaml",
                str(inputs / "mihomo/server/blocked-domain.yaml"),
                str(mihomo / "server/blocked-domain.mrs"),
            ),
            stage,
        ),
        (
            (
                "mihomo-tool",
                "convert-ruleset",
                "ipcidr",
                "yaml",
                str(inputs / "mihomo/server/ru-ip-ipcidr.yaml"),
                str(mihomo / "server/ru-ip-ipcidr.mrs"),
            ),
            stage,
        ),
    ])
    assert set(result.relative_paths) == set(_files(dist))
    assert _files(dist) == {
        "mihomo/lite/blocked-domain.mrs",
        "mihomo/lite/blocked.yaml",
        "mihomo/lite/ru-ip-ipcidr.mrs",
        "mihomo/lite/ru-ip.yaml",
        "mihomo/server/blocked-domain.mrs",
        "mihomo/server/blocked.yaml",
        "mihomo/server/ru-ip-ipcidr.mrs",
        "mihomo/server/ru-ip.yaml",
        "raw/lite/domains/blocked.txt",
        "raw/lite/ip/ru-ip.txt",
        "raw/server/domains/blocked.txt",
        "raw/server/ip/ru-ip.txt",
        "sing-box/lite/blocked.json",
        "sing-box/lite/blocked.srs",
        "sing-box/lite/ru-ip.json",
        "sing-box/lite/ru-ip.srs",
        "sing-box/server/blocked.json",
        "sing-box/server/blocked.srs",
        "sing-box/server/ru-ip.json",
        "sing-box/server/ru-ip.srs",
        "xray/geoip-lite.dat",
        "xray/geoip.dat",
        "xray/geosite-lite.dat",
        "xray/geosite.dat",
    }
    assert json.loads((dist / "sing-box/lite/blocked.json").read_text()) == {
        "version": 1,
        "rules": [{"domain": ["blocked.example"]}],
    }
    assert (dist / "mihomo/lite/blocked.yaml").read_text() == (
        "payload:\n  - DOMAIN,blocked.example\n"
    )
    assert not (dist / ".compiler-inputs").exists()
    assert not stage.exists()


def test_generate_all_provides_empty_private_geosite_group_to_both_dlc_builds(
    tmp_path,
):
    runner = FakeRunner()
    tools = NativeTools(
        runner=runner,
        dlc="dlc-tool",
        geoip="geoip-tool",
        sing_box="sing-box-tool",
        mihomo="mihomo-tool",
    )

    generate_all(build(), tmp_path / "dist", tools)

    assert set(runner.dlc_sources) == {
        tmp_path / ".dist.generate/.compiler-inputs/xray/lite/geosite",
        tmp_path / ".dist.generate/.compiler-inputs/xray/server/geosite",
    }
    assert all(source["private"] == "" for source in runner.dlc_sources.values())


@pytest.mark.parametrize(
    "tool", ["dlc-tool", "geoip-tool", "sing-box-tool", "mihomo-tool"]
)
def test_generate_all_requires_each_compiler_to_create_its_output(tool, tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "known-good").write_text("preserved\n")

    with pytest.raises(GenerationError, match="did not create"):
        generate_all(
            build(),
            dist,
            NativeTools(
                runner=FakeRunner(omit=tool),
                dlc="dlc-tool",
                geoip="geoip-tool",
                sing_box="sing-box-tool",
                mihomo="mihomo-tool",
            ),
        )

    assert _files(dist) == {"known-good"}


def test_generate_all_preserves_previous_dist_when_a_tool_fails(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "known-good").write_text("preserved\n")

    with pytest.raises(GenerationError, match="sing-box.*simulated"):
        generate_all(
            build(),
            dist,
            NativeTools(
                runner=FakeRunner(fail="sing-box-tool"),
                dlc="dlc-tool",
                geoip="geoip-tool",
                sing_box="sing-box-tool",
                mihomo="mihomo-tool",
            ),
        )

    assert _files(dist) == {"known-good"}


def test_generate_all_does_not_claim_mrs_support_for_keyword_rules(tmp_path):
    keyword = Category(
        "search", frozenset({_entry(RuleKind.DOMAIN_KEYWORD, "needle")})
    )
    dataset = Dataset({"search": keyword})
    rendered = ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))

    generate_all(
        rendered,
        tmp_path / "dist",
        NativeTools(
            runner=FakeRunner(),
            dlc="dlc-tool",
            geoip="geoip-tool",
            sing_box="sing-box-tool",
            mihomo="mihomo-tool",
        ),
    )

    assert (tmp_path / "dist/mihomo/lite/search.yaml").is_file()
    assert not (tmp_path / "dist/mihomo/lite/search.mrs").exists()


def test_generate_all_does_not_publish_partial_mrs_for_mixed_keyword_category(
    tmp_path,
):
    blocked = Category(
        "blocked",
        frozenset(
            {
                _entry(RuleKind.DOMAIN, "exact.example"),
                _entry(RuleKind.DOMAIN_KEYWORD, "needle"),
            }
        ),
    )
    dataset = Dataset({"blocked": blocked})
    rendered = ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))

    generated = generate_all(
        rendered,
        tmp_path / "dist",
        NativeTools(
            runner=FakeRunner(),
            dlc="dlc-tool",
            geoip="geoip-tool",
            sing_box="sing-box-tool",
            mihomo="mihomo-tool",
        ),
    )

    assert "mihomo/lite/blocked.yaml" in generated.relative_paths
    assert not any(
        path.startswith("mihomo/lite/blocked") and path.endswith(".mrs")
        for path in generated.relative_paths
    )


def test_generate_all_uses_collision_free_behavior_suffixes(tmp_path):
    mixed = Category(
        "foo",
        frozenset(
            {
                _entry(RuleKind.DOMAIN, "foo.example"),
                _entry(RuleKind.CIDR, "203.0.113.0/24"),
            }
        ),
    )
    similarly_named = Category(
        "foo-domain", frozenset({_entry(RuleKind.DOMAIN, "other.example")})
    )
    dataset = Dataset({"foo": mixed, "foo-domain": similarly_named})
    rendered = ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))

    generated = generate_all(
        rendered,
        tmp_path / "dist",
        NativeTools(
            runner=FakeRunner(),
            dlc="dlc-tool",
            geoip="geoip-tool",
            sing_box="sing-box-tool",
            mihomo="mihomo-tool",
        ),
    )

    assert {
        "mihomo/lite/foo-domain.mrs",
        "mihomo/lite/foo-ipcidr.mrs",
        "mihomo/lite/foo-domain-domain.mrs",
    }.issubset(generated.relative_paths)


_PINNED_TOOLS = ("dlc", "geoip", "sing-box", "mihomo", "xray")
_MISSING_PINNED_TOOLS = tuple(
    executable for executable in _PINNED_TOOLS if shutil.which(executable) is None
)


@pytest.mark.docker_integration
@pytest.mark.skipif(
    bool(_MISSING_PINNED_TOOLS),
    reason=(
        "Task 10 pinned builder image is not installed; missing native tools: "
        + ", ".join(_MISSING_PINNED_TOOLS)
    ),
)
def test_pinned_docker_tools_compile_and_load_domain_and_cidr_for_every_engine(
    tmp_path,
):
    rendered = build()
    tools = NativeTools(runner=ToolRunner(timeout_seconds=30))

    generated = generate_all(rendered, tmp_path / "dist", tools)
    report = validate_build(
        rendered,
        tmp_path / "dist",
        ValidationThresholds(check_determinism=False),
        tools,
    )

    assert "xray/geosite.dat" in generated.relative_paths
    assert "xray/geoip.dat" in generated.relative_paths
    assert "sing-box/server/blocked.srs" in generated.relative_paths
    assert "sing-box/server/ru-ip.srs" in generated.relative_paths
    assert "mihomo/server/blocked-domain.mrs" in generated.relative_paths
    assert "mihomo/server/ru-ip-ipcidr.mrs" in generated.relative_paths
    assert report.native_checks == 12

    corrupted = tmp_path / "dist/mihomo/server/blocked-domain.mrs"
    corrupted.write_bytes(b"corrupt MRS\n")
    with pytest.raises(ValidationError, match="Mihomo MRS load failed"):
        validate_build(
            rendered,
            tmp_path / "dist",
            ValidationThresholds(check_determinism=False),
            tools,
        )


def build() -> ResolvedBuild:
    blocked = Category(
        "blocked", frozenset({_entry(RuleKind.DOMAIN, "blocked.example")})
    )
    ru_ip = Category(
        "ru-ip", frozenset({_entry(RuleKind.CIDR, "203.0.113.0/24")})
    )
    dataset = Dataset({"blocked": blocked, "ru-ip": ru_ip})
    return ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))


def _entry(kind: RuleKind, value: str) -> RuleEntry:
    return RuleEntry(kind, value, frozenset({"fixture"}))


def _flag(command: tuple[str, ...], name: str) -> str:
    prefix = f"{name}="
    return next(
        argument.removeprefix(prefix)
        for argument in command
        if argument.startswith(prefix)
    )


def _files(root: Path) -> set[str]:
    return {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
    }

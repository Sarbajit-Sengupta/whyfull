import json

from conftest import make_ctx
from whyfull.checks import podman
from whyfull.model import INFO, REVIEW


def test_rootful_reclaimable_counts_and_safe_read_commands(root, monkeypatch):
    monkeypatch.setattr(podman, "MIN_BYTES", 20000)
    root.mkdir(podman.ROOT)
    root.commands[("podman", "system", "df", "--format", "json")] = json.dumps([
        {"Type": "Images", "RawReclaimable": 50000},
        {"Type": "Containers", "Reclaimable": "30kB (50%)"},
        {"Type": "Local Volumes", "RawReclaimable": 90000},
    ])
    findings = list(podman.run(make_ctx(root.system())))
    assert [f.bytes for f in findings] == [50000, 30000]
    assert all(f.risk == REVIEW for f in findings)
    assert findings[0].fix == ["podman image prune -a -f"]
    assert findings[1].fix == ["podman container prune -f"]


def test_rootless_inventory_runs_as_owner(root, monkeypatch):
    monkeypatch.setattr(podman, "MIN_BYTES", 20000)
    root.mkdir("/home/alice/.local/share/containers/storage")
    root.commands[("podman", "--version")] = "podman version fixture"
    root.commands[("sudo", "-u", "alice", "-H", "podman", "system", "df", "--format", "json")] = json.dumps([
        {"Type": "Images", "RawReclaimable": 50000},
    ])
    finding, = list(podman.run(make_ctx(root.system())))
    assert finding.bytes == 50000
    assert finding.fix == ["sudo -u alice -H podman image prune -a -f"]


def test_unavailable_rootless_inventory_is_total_usage_not_reclaimable(root, monkeypatch):
    monkeypatch.setattr(podman, "MIN_BYTES", 20000)
    root.write("/home/alice/.local/share/containers/storage/layer", size=50000)
    root.commands[("podman", "--version")] = "podman version fixture"
    finding, = list(podman.run(make_ctx(root.system())))
    assert finding.risk == INFO
    assert "not an estimate of reclaimable" in finding.detail
    assert not any("prune -" in command for command in finding.fix)


def test_bad_rootful_output_and_missing_tool_do_not_claim_space(root):
    root.mkdir(podman.ROOT)
    assert list(podman.run(make_ctx(root.system()))) == []
    for output in ("broken", "null", "{}", "[null]", '[{"Type":"Images","RawReclaimable":-1}]'):
        root.commands[("podman", "system", "df", "--format", "json")] = output
        assert list(podman.run(make_ctx(root.system()))) == []


def test_non_target_storage_and_small_inventories_are_not_reported(root):
    root.mkdir(podman.ROOT)
    root.commands[("podman", "system", "df", "--format", "json")] = '[{"Type":"Images","RawReclaimable":1}]'
    assert list(podman.run(make_ctx(root.system()))) == []
    root.commands[("podman", "system", "df", "--format", "json")] = '[{"Type":"Images","RawReclaimable":500000000}]'
    root.mounts.append((podman.ROOT, "ext4", "/dev/sdb1"))
    assert list(podman.run(make_ctx(root.system()))) == []

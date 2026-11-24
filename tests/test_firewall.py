import pytest
from types import SimpleNamespace
from unittest.mock import patch

from happ_killswitch.firewall import Endpoint, Nftables, render_rules


def test_vpn_policy_allows_server_and_configured_tun_for_both_families():
    text = render_rules("vpn", (Endpoint("192.0.2.10", 443, "tcp"), Endpoint("2001:db8::10", 8443, "udp")), "happ0")
    assert "policy drop" in text
    assert "ip daddr 192.0.2.10 tcp dport 443 accept" in text
    assert "ip6 daddr 2001:db8::10 udp dport 8443 accept" in text
    assert 'oifname "happ0" accept' in text
    assert "ct state established" not in text


def test_lock_policy_has_no_non_loopback_allow_rules():
    text = render_rules("lock")
    assert 'oifname "lo" accept' in text
    assert "policy drop" in text
    assert "daddr" not in text
    assert "oifname \"tun" not in text


def test_replacement_uses_atomic_legacy_delete_syntax():
    text = render_rules("lock", replace_existing=True)
    assert text.startswith("delete table inet happ_killswitch\n")
    assert "destroy table" not in text
    assert "table inet happ_killswitch {" in text


def test_vpn_policy_requires_endpoint():
    with pytest.raises(ValueError, match="хотя бы один"):
        render_rules("vpn")


def test_interface_name_is_escaped_or_rejected():
    with pytest.raises(ValueError, match="Некорректное имя TUN"):
        render_rules("vpn", (Endpoint("192.0.2.10", 443, "tcp"),), 'bad"name')


def test_apply_replaces_existing_table_in_one_ruleset_batch():
    outputs = [
        SimpleNamespace(returncode=0, stdout='{"nftables":[{"table":{"family":"inet","name":"happ_killswitch"}}]}', stderr=""),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]
    with patch("happ_killswitch.firewall.subprocess.run", side_effect=outputs) as run:
        Nftables("nft").apply("lock")
    assert run.call_count == 2
    batch = run.call_args.args[0]
    assert batch == ["nft", "-f", "-"]
    assert run.call_args.kwargs["input"].startswith("delete table inet happ_killswitch\n")


def test_apply_creates_table_without_delete_when_absent():
    outputs = [
        SimpleNamespace(returncode=0, stdout='{"nftables":[]}', stderr=""),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]
    with patch("happ_killswitch.firewall.subprocess.run", side_effect=outputs) as run:
        Nftables("nft").apply("lock")
    assert not run.call_args.kwargs["input"].startswith("delete table")


def test_validate_uses_nft_check_without_applying():
    outputs = [
        SimpleNamespace(returncode=0, stdout='{"nftables":[]}', stderr=""),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]
    with patch("happ_killswitch.firewall.subprocess.run", side_effect=outputs) as run:
        Nftables("nft").validate("vpn", (Endpoint("192.0.2.10", 443, "tcp"),), "tun0")
    assert run.call_args.args[0] == ["nft", "--check", "-f", "-"]
    assert "policy drop" in run.call_args.kwargs["input"]

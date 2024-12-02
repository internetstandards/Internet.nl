import time


def test_unbound_ldns_signzone_cron(trigger_cron, docker_compose_exec):
    """Ensure DNS zones are resigned regurarly."""

    def get_rrsig_expiry():
        return int(
            docker_compose_exec(
                "app", "dig x.a.conn.test-ns-signed.internet.test  +dnssec @unbound|grep 'RRSIG A'"
            ).split()[8]
        )

    # get expiry time field from RRSIG record
    expiry = get_rrsig_expiry()

    time.sleep(1)

    new_expiry = get_rrsig_expiry()

    assert expiry == new_expiry, "sanity check"

    # resign zones via cron script
    print(trigger_cron("weekly/unbound_signzones", service="cron-docker", suffix="-docker"))

    time.sleep(1)

    # get expiry time field from RRSIG record
    new_expiry = get_rrsig_expiry()

    assert int(expiry) < int(new_expiry)

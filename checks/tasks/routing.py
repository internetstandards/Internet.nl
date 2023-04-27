# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
import ipaddress
import json
import requests
import unbound

from django.conf import settings

from . import SetupUnboundContext

from typing import Any, Dict, List, NewType, Tuple, Type, TypeVar

from checks.http_client import http_get

Asn = NewType("Asn", int)
Ip = NewType("Ip", str)
Prefix = NewType("Prefix", str)
Rp = TypeVar("Rp", bound="RelyingPartySoftware")
Rv = TypeVar("Rv", bound="RouteView")
T = TypeVar("T", bound=SetupUnboundContext)
AsnPrefix = Tuple[Asn, Prefix]


class Error(Exception):
    """Base-class for all exceptions raised by this module."""


class InvalidAsnError(Error):
    """There was a problem with the obtained AS number."""


class InvalidIPError(Error):
    """There was a problem with the provided IP address."""


class NoRoutesError(Error):
    """No routes where found for the given prefix."""


class BGPSourceUnavailableError(NoRoutesError):
    """There was a problem with the availability of BGP data."""


class RelyingPartyUnvailableError(Error):
    """There was a problem with the availability of the Relying Party Software."""


class RouteView(ABC):
    """A view on Internet routing data for a given IP address.

    Routing data in the context of this class concerns:
      1. pairs of origin ASN and prefix covering a given IP,
      2. published ROAs covering a given IP, and
      3. the outcome of Route Origin Validation for (1) and (2).

    Implementations can instantiate a RouteView based on
      - a BGP source (using the `from_bgp` constructor, which yields (1)). This
        can then be supplemented by (2) and (3) by calling `validate` on the
        instance, passing an implementation of a `RelyingPartySoftware`, or
      - `RelyingPartySoftware` for RPKI (using the `from_rpki` constructor,
        which yields (2)). This is only intended as a fallback, because (3) is
        unavailable without (1).
      - validity
        dict containing validation state, reason (if applicable) and vrps,
        indexed by (asn, prefix). Used by from_rpki()
    """

    def __init__(self, ip: Ip, routes: List[AsnPrefix], validity: Dict[AsnPrefix, Dict] = None) -> None:
        """Initialize RouteView.

        Args:
        ip
            subject IP address for the RouteView
        routes
            list of (origin asn, prefix) pairs
        """
        self.ip = ip
        self.routes = routes
        self.validity = validity if validity else {}

    def __len__(self):
        """Returns number of routes in this RouteView.

        A length of zero corresponds to either failure to obtain a BGP data, or
        an absense of announcements for a given prefix."""
        return len(self.routes)

    @classmethod
    @abstractmethod
    def from_bgp(cls: Type[Rv], task: T, ip: Ip) -> Rv:
        """Construct a RouteView from a source of BGP data."""

    @classmethod
    def from_rpki(cls: Type[Rv], task: T, rp: Type[Rp], ip: Ip) -> Rv:
        """Construct a (partial) RouteView from a source of RPKI data.

        This looks up covering ROAs for a given ip by performing route origin
        validation against a maximum length prefix and ASN0. It is only intended
        as a fallback to show ROA info to the user even if there is no BGP prefix.
        Without a view on BGP routes, it is meaningless to perform RPKI validation
        on the inferred information.

        Raises:
            RelyingPartyUnavailableError: Relying Party Software not available.
        """
        prefix = ipaddress.ip_network(ip)
        roas = rp.lookup(task, prefix)

        # roa dict indexed by (ASN0, max length prefix),
        # we don't have actual routing information
        return cls(ip, [], {(0, prefix.compressed): roas})

    def validate(self, task: T, rp: Type[Rp]) -> None:
        """Validate pairs of asn, prefix using a provided `RelyingPartySoftware`.

        Raises:
            NoRoutesError: No routes where found, Route Origin Validation is meaningless.
            RelyingPartyUnavailableError: Relying Party Software not available.
        """
        if not self.routes:
            raise NoRoutesError

        for asn, prefix in self.routes:
            result = rp.validate(task, asn, prefix)
            self.validity[(asn, prefix)] = result


class TeamCymruIPtoASN(RouteView):
    """RouteView based on the Team Cymru IP to ASN mapping service."""

    @classmethod
    def from_bgp(cls: Type[Rv], task: T, ip: Ip) -> Rv:
        """Construct a RouteView based on the Team Cymru IP to ASN mapping service."""
        pairs = TeamCymruIPtoASN.asn_prefix_pairs_for_ip(task, ip)

        return cls(ip, pairs)

    @staticmethod
    def asn_prefix_pairs_for_ip(task: T, ip_in: Ip) -> List[AsnPrefix]:
        """Use the Team Cymru IP to ASN mapping service via DNS.

        see: https://team-cymru.com/community-services/ip-asn-mapping/#dns

        Raises:
            InvalidIPError: for invalid ip_in
            BGPSourceUnavailableError: when DNS resolving returns SERVFAIL
        """
        if task is None:
            task = SetupUnboundContext()
        ip2asn_query = TeamCymruIPtoASN.ip_to_dns_query(ip_in)

        result = task.async_resolv(ip2asn_query, unbound.RR_TYPE_TXT)
        if result["nxdomain"]:
            return []
        elif result["rcode"] == unbound.RCODE_SERVFAIL:
            raise BGPSourceUnavailableError(
                f"Team Cymru IP to ASN mapping service returned SERVFAIL for {ip2asn_query} IN TXT?"
            )
        else:
            result = [unbound.ub_data.dname2str(d) for d in result["data"].data]

        # The values in the TXT record are separated by '|' and the ASN is the
        # first value. There may be more than one ASN, separated by a space.
        # The second value contains the prefix.
        asn_prefix_pairs = []
        for txt in result:
            try:
                asns = txt[0].split("|")[0].strip().split(" ")
                prefix = txt[0].split("|")[1].strip()

                # Check that we didn't get any gibberish back.
                ipaddress.ip_network(prefix)
                for asn in asns:
                    if int(asn) >= 2**32:
                        raise InvalidAsnError
            except (ValueError, IndexError, InvalidAsnError) as error:
                raise BGPSourceUnavailableError(
                    "Team Cymru IP to ASN mapping service returned invalid value for "
                    f"{ip2asn_query} IN TXT: {txt}: {error}"
                )

            for asn in asns:
                asn_prefix_pairs.append((asn, prefix))

        return asn_prefix_pairs

    @staticmethod
    def ip_to_dns_query(ip_in: str) -> str:
        """
        Convert an IP address to a Cymru origin ASN query DNS label.
        """
        try:
            ip = ipaddress.ip_address(ip_in)
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped

            # Reverse the IP. In case of IPv6 we need the exploded address.
            if ip.version == 4:
                # note we query for the /24 on the assumption that more
                # specifics are not globally routable.  This anonymizes the
                # specific IPs looked up and improves our chances of hitting
                # our resolver cache.
                split_ip = str(ip).split(".")[0:3]
                split_ip.reverse()
                reversed_ip = ".".join(split_ip)
                ip2asn_query = f"{reversed_ip}.origin.asn.cymru.com."
            elif ip.version == 6:
                exploded_ip = str(ip.exploded)
                # note we query for the /48 on the assumption that more
                # specifics are not globally routable.  This anonymizes the
                # specific IPs looked up and improves our chances of hitting
                # our resolver cache.
                reversed_ip = exploded_ip.replace(":", "")[11::-1]
                reversed_ip = ".".join(reversed_ip)
                ip2asn_query = f"{reversed_ip}.origin6.asn.cymru.com."
            else:
                raise InvalidIPError(f"Unknown IP version for address {ip_in}.")
        except ValueError:
            raise InvalidIPError(f"Error parsing IP address {ip_in}.")
        return ip2asn_query


class RelyingPartySoftware:
    """Abstract base class for implementations of Relying Party Software for RPKI/ROV.

    An implementation should provide:
      - validation of a given origin asn and prefix against
        published Route Origin Authorisations in RPKI.
      - lookup of ROAs covering a given IP address in absence of information on
        originating ASNs
    """

    @staticmethod
    @abstractmethod
    def lookup(task: T, prefix_in: Prefix) -> Dict[str, Any]:
        """Look up ROAs covering a given prefix."""

    @staticmethod
    @abstractmethod
    def validate(task: T, asn: Asn, prefix: Prefix) -> Dict[str, Any]:
        """Validate a origin ASN and prefix against published ROAs."""


class Routinator(RelyingPartySoftware):
    """Wrapper for access to the Routinator Relying Party Software for ROV."""

    @staticmethod
    def lookup(task: T, prefix: Prefix) -> Dict[str, Any]:
        """Look up covering ROAs by attempting to validate against ASN0.

        This is a hack to fetch covering ROAs for a given prefix.

        Raises:
            RelyingPartyUnavailableError
        """
        result = Routinator.validate(task, Asn(0), prefix)

        # no routes to validate against
        result["state"] = None
        result["reason"] = None

        return result

    @staticmethod
    def validate(task: T, asn: Asn, prefix: Prefix) -> Dict[str, Any]:
        """Use routinator to perform Route Origin Validation.

        Raises:
            RelyingPartyUnavailableError
        """
        reason = None
        vrps = {}

        try:
            output = Routinator.query(task, asn, prefix)
            validity = output["validated_route"]["validity"]

            state = validity["state"].lower()

            if state not in ("valid", "invalid", "not-found"):
                raise ValueError

            if state == "valid":
                vrps = validity["VRPs"]["matched"]
            elif state == "invalid":
                reason = validity["reason"]
                vrps = validity["VRPs"][f"unmatched_{reason}"]

            for vrp in vrps:
                vrp["asn"] = vrp["asn"][2:]  # strip leading 'AS'

                # input validation
                if int(vrp["asn"]) >= 2**32:
                    raise ValueError
                ipaddress.ip_network(vrp["prefix"])
                int(vrp["max_length"])

        except (json.JSONDecodeError, ValueError):
            raise RelyingPartyUnvailableError

        return {"state": state, "reason": reason, "vrps": vrps}

    @staticmethod
    def query(task: T, asn: Asn, prefix: Prefix) -> Dict:
        """Query Routinator's /api/v1/validity endpoint and return json response.

        Note that Routinator's API is unavailable during its initial validation run.

        Raises:
            RelyingPartyUnavailableError
        """
        request = f"{settings.ROUTINATOR_URL}/{asn}/{prefix}"
        try:
            response = http_get(request)

            # throw exception during Routinator initialization
            response.raise_for_status()

            return response.json()
        except requests.RequestException as e:
            raise RelyingPartyUnvailableError(str(e))

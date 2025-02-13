from pyavd.api.ip_addressing import AvdIpAddressing, get_ip_from_pool
import json
import sys

TEST_LOOKUP = {
    "SPINE01": "1.1.1.1",
    "SPINE02": "1.1.1.2",
    "LEAF01": "1.1.1.3",
    "LEAF02": "1.1.1.4",
    "LEAF03": "1.1.1.5",
    "LEAF04": "1.1.1.6",
}


class CustomAvdIpAddressing(AvdIpAddressing):

    def p2p_uplinks_ip(self, uplink_switch_index: int) -> str:
        """Return Child IP for P2P Uplinks."""
        # uplink_switch_index = int(uplink_switch_index)
        # if template_path := self.shared_utils.ip_addressing_templates.get("p2p_uplinks_ip"):
        #     return self._template(
        #         template_path,
        #         uplink_switch_index=uplink_switch_index,
        #     )

        # prefixlen = self._fabric_ip_addressing_p2p_uplinks_ipv4_prefix_length
        # p2p_ipv4_pool, offset = self._get_p2p_ipv4_pool_and_offset(uplink_switch_index)

        # return get_ip_from_pool(p2p_ipv4_pool, prefixlen, offset, 1)

        stuff = self._hostvars.get("switch")
        serial_no = stuff.get("serial_number")
        prefixlen = self._fabric_ip_addressing_p2p_uplinks_ipv4_prefix_length
        p2p_ipv4_pool, offset = self._get_p2p_ipv4_pool_and_offset(uplink_switch_index)
        ip = get_ip_from_pool(p2p_ipv4_pool, prefixlen, offset, 1)

        print("Uplinks IP")
        print(f"IP: {ip}")
        print(f"Offset: {offset}")
        print(serial_no)
        print(uplink_switch_index)

        # ip = TEST_LOOKUP.get(serial_no)

        # return ip

        return super().p2p_uplinks_ip(uplink_switch_index)

    def p2p_uplinks_peer_ip(self, uplink_switch_index: int) -> str:
        """Return Parent IP for P2P Uplinks."""
        # uplink_switch_index = int(uplink_switch_index)
        # if template_path := self.shared_utils.ip_addressing_templates.get("p2p_uplinks_peer_ip"):
        #     return self._template(
        #         template_path,
        #         uplink_switch_index=uplink_switch_index,
        #     )

        # prefixlen = self._fabric_ip_addressing_p2p_uplinks_ipv4_prefix_length
        # p2p_ipv4_pool, offset = self._get_p2p_ipv4_pool_and_offset(uplink_switch_index)

        # return get_ip_from_pool(p2p_ipv4_pool, prefixlen, offset, 0)

        stuff = self._hostvars.get("switch")
        serial_no = stuff.get("serial_number")
        prefixlen = self._fabric_ip_addressing_p2p_uplinks_ipv4_prefix_length
        p2p_ipv4_pool, offset = self._get_p2p_ipv4_pool_and_offset(uplink_switch_index)
        ip = get_ip_from_pool(p2p_ipv4_pool, prefixlen, offset, 0)
        print("Uplink Peer IP")
        print(f"IP: {ip}")
        print(f"Offset: {offset}")
        print(serial_no)
        print(uplink_switch_index)

        return super().p2p_uplinks_peer_ip(uplink_switch_index)

    def mlag_ibgp_peering_ip_primary(self, mlag_ibgp_peering_ipv4_pool: str) -> str:
        """Return IP for L3 Peerings in VRFs for MLAG Primary."""
        if template_path := self.shared_utils.ip_addressing_templates.get(
            "mlag_ibgp_peering_ip_primary"
        ):
            return self._template(
                template_path,
                vrf={"mlag_ibgp_peering_ipv4_pool": mlag_ibgp_peering_ipv4_pool},
            )

        return self._mlag_ip(mlag_ibgp_peering_ipv4_pool, 0)

    def mlag_ibgp_peering_ip_secondary(self, mlag_ibgp_peering_ipv4_pool: str) -> str:
        """Return IP for L3 Peerings in VRFs for MLAG Secondary."""
        if template_path := self.shared_utils.ip_addressing_templates.get(
            "mlag_ibgp_peering_ip_secondary"
        ):
            return self._template(
                template_path,
                vrf={"mlag_ibgp_peering_ipv4_pool": mlag_ibgp_peering_ipv4_pool},
            )

        return self._mlag_ip(mlag_ibgp_peering_ipv4_pool, 1)

    def mlag_ip_primary(self) -> str:
        """
        Return IP for MLAG Primary.

        Default pool is "mlag_peer_ipv4_pool"
        """
        if self.shared_utils.mlag_peer_address_family == "ipv6":
            if template_path := self.shared_utils.ip_addressing_templates.get(
                "mlag_ip_primary"
            ):
                return self._template(
                    template_path,
                    mlag_primary_id=self._mlag_primary_id,
                    mlag_secondary_id=self._mlag_secondary_id,
                    switch_data={
                        "combined": {"mlag_peer_ipv6_pool": self._mlag_peer_ipv6_pool}
                    },
                )

            return self._mlag_ip(
                self._mlag_peer_ipv6_pool, 0, self.shared_utils.mlag_peer_address_family
            )

        if template_path := self.shared_utils.ip_addressing_templates.get(
            "mlag_ip_primary"
        ):
            return self._template(
                template_path,
                mlag_primary_id=self._mlag_primary_id,
                mlag_secondary_id=self._mlag_secondary_id,
                switch_data={
                    "combined": {"mlag_peer_ipv4_pool": self._mlag_peer_ipv4_pool}
                },
            )

        return self._mlag_ip(self._mlag_peer_ipv4_pool, 0)

    def mlag_ip_secondary(self) -> str:
        """
        Return IP for MLAG Secondary.

        Default pool is "mlag_peer_ipv4_pool"
        """
        if self.shared_utils.mlag_peer_address_family == "ipv6":
            if template_path := self.shared_utils.ip_addressing_templates.get(
                "mlag_ip_secondary"
            ):
                return self._template(
                    template_path,
                    mlag_primary_id=self._mlag_primary_id,
                    mlag_secondary_id=self._mlag_secondary_id,
                    switch_data={
                        "combined": {"mlag_peer_ipv6_pool": self._mlag_peer_ipv6_pool}
                    },
                )

            return self._mlag_ip(
                self._mlag_peer_ipv6_pool, 1, self.shared_utils.mlag_peer_address_family
            )

        if template_path := self.shared_utils.ip_addressing_templates.get(
            "mlag_ip_secondary"
        ):
            return self._template(
                template_path,
                mlag_primary_id=self._mlag_primary_id,
                mlag_secondary_id=self._mlag_secondary_id,
                switch_data={
                    "combined": {"mlag_peer_ipv4_pool": self._mlag_peer_ipv4_pool}
                },
            )

        return self._mlag_ip(self._mlag_peer_ipv4_pool, 1)

    def mlag_l3_ip_primary(self) -> str:
        """
        Return IP for L3 Peerings for MLAG Primary.

        Default pool is "mlag_peer_l3_ipv4_pool"
        """
        if template_path := self.shared_utils.ip_addressing_templates.get(
            "mlag_l3_ip_primary"
        ):
            return self._template(
                template_path,
                mlag_primary_id=self._mlag_primary_id,
                mlag_secondary_id=self._mlag_secondary_id,
                switch_data={
                    "combined": {"mlag_peer_l3_ipv4_pool": self._mlag_peer_l3_ipv4_pool}
                },
            )

        return self._mlag_ip(self._mlag_peer_l3_ipv4_pool, 0)

    def mlag_l3_ip_secondary(self) -> str:
        """
        Return IP for L3 Peerings for MLAG Secondary.

        Default pool is "mlag_peer_l3_ipv4_pool"
        """
        if template_path := self.shared_utils.ip_addressing_templates.get(
            "mlag_l3_ip_secondary"
        ):
            return self._template(
                template_path,
                mlag_primary_id=self._mlag_primary_id,
                mlag_secondary_id=self._mlag_secondary_id,
                switch_data={
                    "combined": {"mlag_peer_l3_ipv4_pool": self._mlag_peer_l3_ipv4_pool}
                },
            )

        return self._mlag_ip(self._mlag_peer_l3_ipv4_pool, 1)

    def p2p_vrfs_uplinks_ip(
        self,
        uplink_switch_index: int,
        vrf: str,  # pylint: disable=unused-argument # NOSONAR # noqa: ARG002
    ) -> str:
        """
        Return Child IP for P2P-VRFs Uplinks.

        Unless overridden in a custom IP addressing module, this will just reuse the regular ip addressing logic.
        """
        # return self.p2p_uplinks_ip(uplink_switch_index)

        return super().p2p_vrfs_uplinks_ip(uplink_switch_index, vrf)

    def p2p_vrfs_uplinks_peer_ip(
        self,
        uplink_switch_index: int,
        vrf: str,  # pylint: disable=unused-argument # NOSONAR # noqa: ARG002
    ) -> str:
        """
        Return Parent IP for P2P-VRFs Uplinks.

        Unless overridden in a custom IP addressing module, this will just reuse the regular ip addressing logic.
        """
        # return self.p2p_uplinks_peer_ip(uplink_switch_index)

        return super().p2p_vrfs_uplinks_peer_ip(uplink_switch_index, vrf)

    def router_id(self) -> str:
        """
        Return IP address for Router ID.

        If "loopback_ipv4_address" is set, it is used.
        Default pool is "loopback_ipv4_pool"
        Default offset from pool is `id + loopback_ipv4_offset`
        """
        # if self._loopback_ipv4_address:
        #     return self._loopback_ipv4_address

        # if template_path := self.shared_utils.ip_addressing_templates.get("router_id"):
        #     return self._template(
        #         template_path,
        #         switch_id=self._id,
        #         loopback_ipv4_pool=self._loopback_ipv4_pool,
        #         loopback_ipv4_offset=self._loopback_ipv4_offset,
        #     )

        # offset = self._id + self._loopback_ipv4_offset
        # return get_ip_from_pool(self._loopback_ipv4_pool, 32, offset, 0)

        return super().router_id()

    def ipv6_router_id(self) -> str:
        """
        Return IPv6 address for Router ID.

        Default pool is "loopback_ipv6_pool"
        Default offset from pool is `id + loopback_ipv6_offset`
        """
        # if template_path := self.shared_utils.ip_addressing_templates.get(
        #     "ipv6_router_id"
        # ):
        #     return self._template(
        #         template_path,
        #         switch_id=self._id,
        #         loopback_ipv6_pool=self._loopback_ipv6_pool,
        #         loopback_ipv6_offset=self._loopback_ipv6_offset,
        #     )

        # offset = self._id + self._loopback_ipv6_offset
        # return get_ip_from_pool(self._loopback_ipv6_pool, 128, offset, 0)

        return super().ipv6_router_id()

    def vtep_ip_mlag(self) -> str:
        """
        Return IP address for VTEP for MLAG Leaf.

        If "vtep_loopback_ipv4_address" is set, it is used.
        Default pool is "vtep_loopback_ipv4_pool"
        Default offset from pool is `mlag_primary_id + loopback_ipv4_offset`
        """
        # if self._vtep_loopback_ipv4_address:
        #     return self._vtep_loopback_ipv4_address

        # if template_path := self.shared_utils.ip_addressing_templates.get(
        #     "vtep_ip_mlag"
        # ):
        #     return self._template(
        #         template_path,
        #         switch_id=self._id,
        #         switch_vtep_loopback_ipv4_pool=self._vtep_loopback_ipv4_pool,
        #         loopback_ipv4_offset=self._loopback_ipv4_offset,
        #         mlag_primary_id=self._mlag_primary_id,
        #         mlag_secondary_id=self._mlag_secondary_id,
        #     )

        # offset = self._mlag_primary_id + self._loopback_ipv4_offset
        # return get_ip_from_pool(self._vtep_loopback_ipv4_pool, 32, offset, 0)

        return super().vtep_ip_mlag()

    def vtep_ip(self) -> str:
        """
        Return IP address for VTEP.

        If "vtep_loopback_ipv4_address" is set, it is used.
        Default pool is "vtep_loopback_ipv4_pool"
        Default offset from pool is `id + loopback_ipv4_offset`
        """
        # if self._vtep_loopback_ipv4_address:
        #     return self._vtep_loopback_ipv4_address

        # if template_path := self.shared_utils.ip_addressing_templates.get("vtep_ip"):
        #     return self._template(
        #         template_path,
        #         switch_id=self._id,
        #         switch_vtep_loopback_ipv4_pool=self._vtep_loopback_ipv4_pool,
        #         loopback_ipv4_offset=self._loopback_ipv4_offset,
        #     )

        # offset = self._id + self._loopback_ipv4_offset
        # return get_ip_from_pool(self._vtep_loopback_ipv4_pool, 32, offset, 0)

        return super().vtep_ip()

    def vrf_loopback_ip(self, pool: str) -> str:
        """
        Return IP address for a Loopback interface based on the given pool.

        Default offset from pool is `id + loopback_ipv4_offset`.

        Used for "vtep_diagnostic.loopback".
        """
        # offset = self.shared_utils.id + self.shared_utils.loopback_ipv4_offset
        # return get_ip_from_pool(pool, 32, offset, 0)

        return super().vrf_loopback_ip(pool)

    def vrf_loopback_ipv6(self, pool: str) -> str:
        """
        Return IPv6 address for a Loopback interface based on the given pool.

        Default offset from pool is `id + loopback_ipv6_offset`.

        Used for "vtep_diagnostic.loopback".
        """
        # offset = self.shared_utils.id + self.shared_utils.loopback_ipv6_offset
        # return get_ip_from_pool(pool, 128, offset, 0)

        return super().vrf_loopback_ipv6(pool)

    def evpn_underlay_l3_multicast_group(
        self,
        underlay_l3_multicast_group_ipv4_pool: str,
        vrf_vni: int,  # pylint: disable=unused-argument # noqa: ARG002
        vrf_id: int,
        evpn_underlay_l3_multicast_group_ipv4_pool_offset: int,
    ) -> str:
        """Return IP address to be used for EVPN underlay L3 multicast group."""
        # offset = vrf_id - 1 + evpn_underlay_l3_multicast_group_ipv4_pool_offset
        # return get_ip_from_pool(underlay_l3_multicast_group_ipv4_pool, 32, offset, 0)

        return super().evpn_underlay_l3_multicast_group(
            underlay_l3_multicast_group_ipv4_pool,
            vrf_vni,
            vrf_id,
            evpn_underlay_l3_multicast_group_ipv4_pool_offset,
        )

    def evpn_underlay_l2_multicast_group(
        self,
        underlay_l2_multicast_group_ipv4_pool: str,
        vlan_id: int,
        underlay_l2_multicast_group_ipv4_pool_offset: int,
    ) -> str:
        """Return IP address to be used for EVPN underlay L2 multicast group."""
        # offset = vlan_id - 1 + underlay_l2_multicast_group_ipv4_pool_offset
        # return get_ip_from_pool(underlay_l2_multicast_group_ipv4_pool, 32, offset, 0)
        return super().evpn_underlay_l2_multicast_group(
            underlay_l2_multicast_group_ipv4_pool,
            vlan_id,
            underlay_l2_multicast_group_ipv4_pool_offset,
        )

    def wan_ha_ip(self) -> str:
        """Return the WAN HA local IP address."""
        # wan_ha_ipv4_pool = self.shared_utils.wan_ha_ipv4_pool
        # prefixlen = self.shared_utils.fabric_ip_addressing_wan_ha_ipv4_prefix_length

        # if self.shared_utils.is_first_ha_peer:
        #     ip_address = get_ip_from_pool(wan_ha_ipv4_pool, prefixlen, 0, 0)
        # else:
        #     ip_address = get_ip_from_pool(wan_ha_ipv4_pool, prefixlen, 0, 1)

        # return f"{ip_address}/{prefixlen}"

        return super().wan_ha_ip()

    def wan_ha_peer_ip(self) -> str:
        """Return the WAN HA peer IP."""
        # wan_ha_ipv4_pool = self.shared_utils.wan_ha_ipv4_pool
        # prefixlen = self.shared_utils.fabric_ip_addressing_wan_ha_ipv4_prefix_length

        # if self.shared_utils.is_first_ha_peer:
        #     ip_address = get_ip_from_pool(wan_ha_ipv4_pool, prefixlen, 0, 1)
        # else:
        #     ip_address = get_ip_from_pool(wan_ha_ipv4_pool, prefixlen, 0, 0)

        # return f"{ip_address}/{prefixlen}"

        return super().wan_ha_peer_ip()

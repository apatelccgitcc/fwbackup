"""Realistic sample Entities.xml content for tests and the demo."""

RULE = """<FirewallRule transactionid="">
  <Name>{name}</Name><Description>{desc}</Description><IPFamily>IPv4</IPFamily><Status>{status}</Status>
  <Position>Bottom</Position><PolicyType>Network</PolicyType>
  <NetworkPolicy>
    <Action>{action}</Action><LogTraffic>{log}</LogTraffic><SkipLocalDestined>Disable</SkipLocalDestined>
    <SourceZones>{src}</SourceZones><DestinationZones>{dst}</DestinationZones>
    <Schedule>All The Time</Schedule>{nets}{svcs}
    <IntrusionPrevention>{ips}</IntrusionPrevention><WebFilter>{wf}</WebFilter>
    <ApplicationControl>Allow All</ApplicationControl><ScanVirus>Disable</ScanVirus>
  </NetworkPolicy>
</FirewallRule>"""


def rule(name, src=("LAN",), dst=("WAN",), action="Accept", log="Enable", status="Enable",
         desc="", srcnet=(), dstnet=(), svcs=(), ips="lantowan_general", wf="Default Workplace Policy"):
    z = lambda zs: "".join(f"<Zone>{x}</Zone>" for x in zs)
    nets = ""
    if srcnet:
        nets += "<SourceNetworks>" + "".join(f"<Network>{n}</Network>" for n in srcnet) + "</SourceNetworks>"
    if dstnet:
        nets += "<DestinationNetworks>" + "".join(f"<Network>{n}</Network>" for n in dstnet) + "</DestinationNetworks>"
    s = ("<Services>" + "".join(f"<Service>{x}</Service>" for x in svcs) + "</Services>") if svcs else ""
    return RULE.format(name=name, desc=desc, status=status, action=action, log=log, src=z(src), dst=z(dst),
                       nets=nets, svcs=s, ips=ips, wf=wf)


def nat(name, orig_dst, xl_dst, svc, inbound="Port1"):
    return f"""<NATRule transactionid=""><Name>{name}</Name><Description></Description><IPFamily>IPv4</IPFamily>
  <Status>Enable</Status><Position>Bottom</Position><LinkedFirewallrule>None</LinkedFirewallrule>
  <OriginalSource>Any</OriginalSource><OriginalDestination>{orig_dst}</OriginalDestination>
  <OriginalService>{svc}</OriginalService><TranslatedSource>Original</TranslatedSource>
  <TranslatedDestination>{xl_dst}</TranslatedDestination><TranslatedService>Original</TranslatedService>
  <InboundInterface><Interface>{inbound}</Interface></InboundInterface></NATRule>"""


def zone(name, ztype, services):
    svc = "".join(f"<{s}>Enable</{s}>" for s in services)
    return f"""<Zone transactionid=""><Name>{name}</Name><Type>{ztype}</Type>
  <ApplianceAccess><AdminServices>{svc}</AdminServices></ApplianceAccess></Zone>"""


def host(name, ip):
    return (f'<IPHost transactionid=""><Name>{name}</Name><IPFamily>IPv4</IPFamily>'
            f'<HostType>IP</HostType><IPAddress>{ip}</IPAddress></IPHost>')


def user(name, group, pptp="Disable", pw="ENC1"):
    return (f'<User transactionid=""><Username>{name}</Username><Name>{name}</Name><Password>{pw}</Password>'
            f'<Group>{group}</Group><L2TP>Disable</L2TP><PPTP>{pptp}</PPTP><Status>Active</Status></User>')


def admin_settings(port="4444"):
    return (f'<AdminSettings transactionid=""><WebAdminSettings><HTTPSport>{port}</HTTPSport>'
            f'<UserPortalHTTPSPort>443</UserPortalHTTPSPort></WebAdminSettings></AdminSettings>')


def config(parts, root="Configuration"):
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<{root} APIVersion="2100.1" IPS_CAT_VER="1">\n'
            + "\n".join(parts) + f"\n</{root}>").encode()


def baseline():
    return [
        zone("LAN", "LAN", ["HTTPS", "SSH", "Ping"]),
        zone("WAN", "WAN", ["UserPortal"]),
        host("FileServer", "10.0.0.10"), host("NVR", "10.0.0.50"),
        rule("Internet Access", desc="LAN to internet"),
        rule("Allow DC traffic", src=("LAN",), dst=("LAN",), dstnet=("FileServer",), svcs=("SMB", "LDAP")),
        rule("VPN to LAN", src=("VPN",), dst=("LAN",), log="Enable"),
        rule("Block outside NA", src=("WAN",), dst=("LAN", "DMZ"), action="Drop"),
        nat("Default SNAT", "Any", "Original", "Any"),
        user("jsmith", "Open Group"),
        admin_settings(),
    ]


def changed():
    """Same firewall a day later with a mix of real changes."""
    p = [
        zone("LAN", "LAN", ["HTTPS", "SSH", "Ping"]),
        zone("WAN", "WAN", ["UserPortal", "HTTPS", "SSLVPN"]),      # webadmin exposed on WAN
        host("FileServer", "10.0.0.10"), host("NVR", "10.0.0.50"), host("Vendor-Support", "203.0.113.25"),
        rule("Block outside NA", src=("WAN",), dst=("LAN", "DMZ"), action="Drop"),   # moved to top
        rule("Internet Access", desc="LAN to internet", log="Disable"),             # logging off
        rule("Allow DC traffic", src=("LAN",), dst=("LAN",), dstnet=("FileServer",), svcs=("SMB", "LDAP", "RDP")),
        rule("NVR remote view", src=("WAN",), dst=("LAN",), dstnet=("NVR",), svcs=("HTTPS",), ips="None"),  # new
        nat("Default SNAT", "Any", "Original", "Any"),
        nat("NVR port forward", "#Port1", "NVR", "HTTPS"),          # new port forward
        user("jsmith", "Open Group", pw="ENC2-reencrypted"),        # only password re-encryption: ignored
        user("vendor1", "Open Group", pptp="Enable"),               # new user
        admin_settings("4444"),
    ]
    # "VPN to LAN" removed
    return p

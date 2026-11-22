##! twigs passive discovery - device identification logs.
##!
##! Loaded by "twigs passive" on top of Zeek's default scripts and any ICS
##! protocol packages that are installed (ICSNPP). It adds small, purpose-built
##! logs carrying only the identity fields twigs needs (vendor, model,
##! firmware, hostnames). Application payloads (e.g. HL7 message bodies,
##! DICOM datasets) are never logged.
##!
##! All logs are de-duplicated per host so that long live captures stay small.

@load base/protocols/mqtt
@load policy/protocols/conn/mac-logging

module TwigsPassive;

export {
    ## How long a (host, value) pair is remembered before it is logged again.
    const dedup_interval = 6 hrs &redef;

    redef enum Log::ID += {
        DHCP_LOG, TCP_FP_LOG, SNMP_LOG, HTTP_LOG, MDNS_LOG, SSDP_LOG,
        WSD_LOG, NBNS_LOG, NTLM_LOG, TLS_LOG, MQTT_LOG, MAC_LOG
    };

    ## DHCP client fingerprint (options 12, 55, 60, 61, 81).
    type DhcpInfo: record {
        ts:             time   &log;
        mac:            string &log &optional;
        ip:             addr   &log &optional;
        hostname:       string &log &optional;
        vendor_class:   string &log &optional;
        param_req_list: string &log &optional;
        client_fqdn:    string &log &optional;
        msg_type:       count  &log &optional;
    };

    ## Passive TCP/IP stack fingerprint taken from SYN and SYN-ACK packets.
    type TcpFpInfo: record {
        ts:        time   &log;
        host:      addr   &log;
        port_:     port   &log;
        role:      string &log;   ##< "client" (SYN) or "server" (SYN-ACK)
        ttl:       count  &log;
        win_size:  count  &log;
        win_scale: int    &log;
        mss:       count  &log;
        sack_ok:   bool   &log;
        df:        bool   &log;
        ts_opt:    bool   &log;
    };

    ## SNMP system group values seen in responses and traps.
    type SnmpInfo: record {
        ts:          time   &log;
        host:        addr   &log;
        sys_descr:   string &log &optional;
        sys_objectid: string &log &optional;
        sys_name:    string &log &optional;
        sys_location: string &log &optional;
        trap_enterprise: string &log &optional;
    };

    ## HTTP Server / User-Agent headers.
    type HttpInfo: record {
        ts:     time   &log;
        host:   addr   &log;
        port_:  port   &log &optional;
        header: string &log;      ##< "server", "user-agent" or "x-powered-by"
        value:  string &log;
    };

    ## mDNS / DNS-SD announcements (PTR, SRV, TXT, A).
    type MdnsInfo: record {
        ts:    time   &log;
        host:  addr   &log;
        rtype: string &log;
        name:  string &log;
        value: string &log &optional;
    };

    ## SSDP / UPnP advertisements (UDP 1900).
    type SsdpInfo: record {
        ts:       time   &log;
        host:     addr   &log;
        method:   string &log &optional;
        st:       string &log &optional;
        usn:      string &log &optional;
        server:   string &log &optional;
        location: string &log &optional;
    };

    ## WS-Discovery Hello / ProbeMatch (UDP 3702).
    type WsdInfo: record {
        ts:     time   &log;
        host:   addr   &log;
        types:  string &log &optional;
        scopes: string &log &optional;
        xaddrs: string &log &optional;
    };

    ## NetBIOS name registrations (UDP 137). The name is first-level encoded
    ## and is decoded by twigs.
    type NbnsInfo: record {
        ts:           time   &log;
        host:         addr   &log;
        encoded_name: string &log;
    };

    ## Windows version reported in NTLM challenges (SMB, HTTP, RDP...).
    type NtlmInfo: record {
        ts:            time   &log;
        host:          addr   &log;
        os_major:      count  &log &optional;
        os_minor:      count  &log &optional;
        os_build:      count  &log &optional;
        nb_computer:   string &log &optional;
        dns_computer:  string &log &optional;
    };

    ## Server certificate identity.
    type TlsInfo: record {
        ts:      time   &log;
        host:    addr   &log;
        port_:   port   &log;
        subject: string &log &optional;
        issuer:  string &log &optional;
        san_dns: string &log &optional;
    };

    ## IP to MAC address, logged when a connection starts. conn.log has the
    ## same information but is only written when the connection ends, which
    ## in continuous capture can be several log rotations later.
    type MacInfo: record {
        ts:   time   &log;
        host: addr   &log;
        mac:  string &log;
    };

    ## MQTT client identity.
    type MqttInfo: record {
        ts:        time   &log;
        host:      addr   &log;
        client_id: string &log;
        username:  string &log &optional;
        will_topic: string &log &optional;
    };
}

# UDP payloads needed by the SSDP, WS-Discovery and NetBIOS parsers below.
redef udp_content_delivery_ports_orig += { [1900/udp] = T, [3702/udp] = T, [137/udp] = T };
redef udp_content_delivery_ports_resp += { [1900/udp] = T, [3702/udp] = T, [137/udp] = T };

global seen: set[string] &create_expire=dedup_interval;

## True the first time a key is seen within dedup_interval.
function first(key: string): bool
    {
    if ( key in seen )
        return F;
    add seen[key];
    return T;
    }

event zeek_init() &priority=5
    {
    Log::create_stream(DHCP_LOG,   [$columns=DhcpInfo,  $path="twigs_dhcp"]);
    Log::create_stream(TCP_FP_LOG, [$columns=TcpFpInfo, $path="twigs_tcp_fp"]);
    Log::create_stream(SNMP_LOG,   [$columns=SnmpInfo,  $path="twigs_snmp"]);
    Log::create_stream(HTTP_LOG,   [$columns=HttpInfo,  $path="twigs_http"]);
    Log::create_stream(MDNS_LOG,   [$columns=MdnsInfo,  $path="twigs_mdns"]);
    Log::create_stream(SSDP_LOG,   [$columns=SsdpInfo,  $path="twigs_ssdp"]);
    Log::create_stream(WSD_LOG,    [$columns=WsdInfo,   $path="twigs_wsd"]);
    Log::create_stream(NBNS_LOG,   [$columns=NbnsInfo,  $path="twigs_nbns"]);
    Log::create_stream(NTLM_LOG,   [$columns=NtlmInfo,  $path="twigs_ntlm"]);
    Log::create_stream(TLS_LOG,    [$columns=TlsInfo,   $path="twigs_tls"]);
    Log::create_stream(MQTT_LOG,   [$columns=MqttInfo,  $path="twigs_mqtt"]);
    Log::create_stream(MAC_LOG,    [$columns=MacInfo,   $path="twigs_mac"]);
    }

# ---------------------------------------------------------------------------
# IP to MAC address, as soon as a connection is seen
# ---------------------------------------------------------------------------
event new_connection(c: connection)
    {
    if ( c$orig?$l2_addr && first(fmt("mac|%s|%s", c$id$orig_h, c$orig$l2_addr)) )
        Log::write(MAC_LOG, MacInfo($ts=network_time(), $host=c$id$orig_h, $mac=c$orig$l2_addr));
    if ( c$resp?$l2_addr && first(fmt("mac|%s|%s", c$id$resp_h, c$resp$l2_addr)) )
        Log::write(MAC_LOG, MacInfo($ts=network_time(), $host=c$id$resp_h, $mac=c$resp$l2_addr));
    }

# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    # Only client messages (DISCOVER=1, REQUEST=3, INFORM=8) describe the client.
    if ( msg$m_type != 1 && msg$m_type != 3 && msg$m_type != 8 )
        return;

    local info = DhcpInfo($ts=network_time(), $mac=msg$chaddr, $msg_type=msg$m_type);
    if ( msg$ciaddr != 0.0.0.0 )
        info$ip = msg$ciaddr;
    else if ( options?$addr_request )
        info$ip = options$addr_request;
    if ( options?$host_name )
        info$hostname = options$host_name;
    if ( options?$vendor_class )
        info$vendor_class = options$vendor_class;
    if ( options?$client_fqdn )
        info$client_fqdn = options$client_fqdn$domain_name;
    if ( options?$param_list )
        {
        local parts: vector of string = vector();
        for ( i in options$param_list )
            parts += fmt("%d", options$param_list[i]);
        info$param_req_list = join_string_vec(parts, ",");
        }

    if ( first(fmt("dhcp|%s|%s|%s|%s", info$mac, info?$hostname ? info$hostname : "",
                   info?$vendor_class ? info$vendor_class : "",
                   info?$param_req_list ? info$param_req_list : "")) )
        Log::write(DHCP_LOG, info);
    }

# ---------------------------------------------------------------------------
# TCP/IP stack fingerprint (SYN = client stack, SYN-ACK = server stack)
# ---------------------------------------------------------------------------
event connection_SYN_packet(c: connection, pkt: SYN_packet)
    {
    local h = pkt$is_orig ? c$id$orig_h : c$id$resp_h;
    local role = pkt$is_orig ? "client" : "server";
    local key = fmt("tcpfp|%s|%s|%d|%d|%d|%d", h, role, pkt$ttl, pkt$win_size, pkt$win_scale, pkt$MSS);
    if ( ! first(key) )
        return;
    Log::write(TCP_FP_LOG, TcpFpInfo($ts=network_time(), $host=h, $port_=c$id$resp_p,
                                     $role=role, $ttl=pkt$ttl, $win_size=pkt$win_size,
                                     $win_scale=pkt$win_scale, $mss=pkt$MSS,
                                     $sack_ok=pkt$SACK_OK, $df=pkt$DF, $ts_opt=pkt?$TSval));
    }

# ---------------------------------------------------------------------------
# SNMP system group (sysDescr, sysObjectID, sysName, sysLocation) and traps
# ---------------------------------------------------------------------------
function snmp_value(v: SNMP::ObjectValue): string
    {
    if ( v?$octets )
        return v$octets;
    if ( v?$oid )
        return v$oid;
    return "";
    }

function log_snmp_bindings(h: addr, bindings: SNMP::Bindings, enterprise: string)
    {
    local info = SnmpInfo($ts=network_time(), $host=h);
    local found = F;
    for ( i in bindings )
        {
        local b = bindings[i];
        local val = snmp_value(b$value);
        if ( val == "" )
            next;
        if ( b$oid == "1.3.6.1.2.1.1.1.0" ) { info$sys_descr = val; found = T; }
        else if ( b$oid == "1.3.6.1.2.1.1.2.0" ) { info$sys_objectid = val; found = T; }
        else if ( b$oid == "1.3.6.1.2.1.1.5.0" ) { info$sys_name = val; found = T; }
        else if ( b$oid == "1.3.6.1.2.1.1.6.0" ) { info$sys_location = val; found = T; }
        }
    if ( enterprise != "" )
        {
        info$trap_enterprise = enterprise;
        found = T;
        }
    if ( ! found )
        return;
    if ( first(fmt("snmp|%s|%s|%s|%s|%s", h, info?$sys_descr ? info$sys_descr : "",
                   info?$sys_objectid ? info$sys_objectid : "",
                   info?$sys_name ? info$sys_name : "", enterprise)) )
        Log::write(SNMP_LOG, info);
    }

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
    {
    # The agent (device) is the side that sends the response.
    log_snmp_bindings(is_orig ? c$id$orig_h : c$id$resp_h, pdu$bindings, "");
    }

event snmp_trap(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::TrapPDU)
    {
    log_snmp_bindings(is_orig ? c$id$orig_h : c$id$resp_h, pdu$bindings, pdu$enterprise);
    }

event snmp_trapV2(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
    {
    log_snmp_bindings(is_orig ? c$id$orig_h : c$id$resp_h, pdu$bindings, "");
    }

# ---------------------------------------------------------------------------
# HTTP Server / X-Powered-By (server side) and User-Agent (client side)
# ---------------------------------------------------------------------------
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    local hdr = "";
    if ( ! is_orig && (name == "SERVER" || name == "X-POWERED-BY") )
        hdr = to_lower(name);
    else if ( is_orig && name == "USER-AGENT" )
        hdr = "user-agent";
    if ( hdr == "" || value == "" )
        return;
    local h = is_orig ? c$id$orig_h : c$id$resp_h;
    if ( first(fmt("http|%s|%s|%s", h, hdr, value)) )
        Log::write(HTTP_LOG, HttpInfo($ts=network_time(), $host=h, $port_=c$id$resp_p,
                                      $header=hdr, $value=value[0:300]));
    }

# ---------------------------------------------------------------------------
# mDNS / DNS-SD (UDP 5353). The responder is the device being described.
# ---------------------------------------------------------------------------
function mdns_responder(c: connection): addr
    {
    # Announcements are sent from the device to 224.0.0.251 / ff02::fb, so the
    # device is the originator. Unicast replies come back from the responder.
    if ( c$id$resp_h == 224.0.0.251 || c$id$resp_h == [ff02::fb] )
        return c$id$orig_h;
    return c$id$resp_p == 5353/udp && c$id$orig_p != 5353/udp ? c$id$resp_h : c$id$orig_h;
    }

function log_mdns(c: connection, msg: dns_msg, rtype: string, name: string, value: string)
    {
    if ( c$id$resp_p != 5353/udp && c$id$orig_p != 5353/udp )
        return;
    if ( ! msg$QR )
        return;
    local h = mdns_responder(c);
    if ( first(fmt("mdns|%s|%s|%s|%s", h, rtype, name, value)) )
        Log::write(MDNS_LOG, MdnsInfo($ts=network_time(), $host=h, $rtype=rtype,
                                      $name=name, $value=value[0:400]));
    }

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    { log_mdns(c, msg, "PTR", ans$query, name); }

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)
    { log_mdns(c, msg, "SRV", ans$query, fmt("%s:%d", target, p)); }

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
    { log_mdns(c, msg, "TXT", ans$query, join_string_vec(strs, ";")); }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    { log_mdns(c, msg, "A", ans$query, fmt("%s", a)); }

# ---------------------------------------------------------------------------
# SSDP, WS-Discovery and NetBIOS name service payload parsers
# ---------------------------------------------------------------------------
function header_value(lines: string_vec, name: pattern): string
    {
    for ( i in lines )
        if ( name in lines[i] )
            return strip(sub(lines[i], /^[^:]*:/, ""));
    return "";
    }

function xml_element(contents: string, element: string): string
    {
    # Matches <prefix:Element ...>value< regardless of namespace prefix.
    local pat = string_to_pattern(fmt("<([A-Za-z0-9_]+:)?%s[^>]*>[^<]*<", element), F);
    local matches = find_all_ordered(contents, pat);
    if ( |matches| == 0 )
        return "";
    local m = matches[0];
    return strip(m[strstr(m, ">"):|m| - 1]);
    }

function parse_ssdp(h: addr, contents: string)
    {
    if ( /^(NOTIFY|HTTP\/1\.[01] 200)/ !in contents )
        return;
    local lines = split_string(contents, /\r?\n/);
    local info = SsdpInfo($ts=network_time(), $host=h, $method=strip(lines[0])[0:40]);
    local v = header_value(lines, /^[Ss][Ee][Rr][Vv][Ee][Rr][ \t]*:/);
    if ( v != "" ) info$server = v[0:200];
    v = header_value(lines, /^[Nn]?[SsTt][Tt][ \t]*:|^[Nn][Tt][ \t]*:/);
    if ( v != "" ) info$st = v[0:200];
    v = header_value(lines, /^[Uu][Ss][Nn][ \t]*:/);
    if ( v != "" ) info$usn = v[0:200];
    v = header_value(lines, /^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn][ \t]*:/);
    if ( v != "" ) info$location = v[0:200];
    if ( first(fmt("ssdp|%s|%s|%s", h, info?$server ? info$server : "", info?$st ? info$st : "")) )
        Log::write(SSDP_LOG, info);
    }

function parse_wsd(h: addr, contents: string)
    {
    if ( /Hello|ProbeMatches|ResolveMatches/ !in contents )
        return;
    local info = WsdInfo($ts=network_time(), $host=h);
    local v = xml_element(contents, "Types");
    if ( v != "" ) info$types = v[0:300];
    v = xml_element(contents, "Scopes");
    if ( v != "" ) info$scopes = v[0:300];
    v = xml_element(contents, "XAddrs");
    if ( v != "" ) info$xaddrs = v[0:300];
    if ( first(fmt("wsd|%s|%s|%s", h, info?$types ? info$types : "", info?$scopes ? info$scopes : "")) )
        Log::write(WSD_LOG, info);
    }

function parse_nbns(h: addr, contents: string)
    {
    # Header (12 bytes) then a length-prefixed 32-byte encoded name.
    if ( |contents| < 46 || bytestring_to_count(contents[12]) != 32 )
        return;
    local opcode = (bytestring_to_count(contents[2]) / 8) % 16;
    # 5 = registration, 8 = refresh: sent by the owner of the name.
    if ( opcode != 5 && opcode != 8 )
        return;
    local enc = contents[13:45];
    if ( first(fmt("nbns|%s|%s", h, enc)) )
        Log::write(NBNS_LOG, NbnsInfo($ts=network_time(), $host=h, $encoded_name=enc));
    }

event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    local h = is_orig ? c$id$orig_h : c$id$resp_h;
    if ( c$id$resp_p == 1900/udp || c$id$orig_p == 1900/udp )
        parse_ssdp(h, contents);
    else if ( c$id$resp_p == 3702/udp || c$id$orig_p == 3702/udp )
        parse_wsd(h, contents);
    else if ( c$id$resp_p == 137/udp || c$id$orig_p == 137/udp )
        parse_nbns(h, contents);
    }

# ---------------------------------------------------------------------------
# NTLM server version (Windows / Windows Embedded based devices)
# ---------------------------------------------------------------------------
event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
    {
    local info = NtlmInfo($ts=network_time(), $host=c$id$resp_h);
    if ( challenge?$version )
        {
        info$os_major = challenge$version$major;
        info$os_minor = challenge$version$minor;
        info$os_build = challenge$version$build;
        }
    if ( challenge?$target_info )
        {
        if ( challenge$target_info?$nb_computer_name )
            info$nb_computer = challenge$target_info$nb_computer_name;
        if ( challenge$target_info?$dns_computer_name )
            info$dns_computer = challenge$target_info$dns_computer_name;
        }
    if ( first(fmt("ntlm|%s|%s", c$id$resp_h, info?$os_build ? info$os_build : 0)) )
        Log::write(NTLM_LOG, info);
    }

# ---------------------------------------------------------------------------
# TLS server certificate subject / issuer
# ---------------------------------------------------------------------------
event ssl_established(c: connection)
    {
    if ( ! c?$ssl || ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 )
        return;
    local f = c$ssl$cert_chain[0];
    if ( ! f?$x509 )
        return;
    local cert = f$x509$certificate;
    local info = TlsInfo($ts=network_time(), $host=c$id$resp_h, $port_=c$id$resp_p,
                         $subject=cert$subject, $issuer=cert$issuer);
    if ( f$x509?$san && f$x509$san?$dns )
        info$san_dns = join_string_vec(f$x509$san$dns, ",")[0:300];
    if ( first(fmt("tls|%s|%s", c$id$resp_h, cert$subject)) )
        Log::write(TLS_LOG, info);
    }

# ---------------------------------------------------------------------------
# MQTT client identity
# ---------------------------------------------------------------------------
event mqtt_connect(c: connection, msg: MQTT::ConnectMsg)
    {
    local info = MqttInfo($ts=network_time(), $host=c$id$orig_h, $client_id=msg$client_id);
    if ( msg?$username )
        info$username = msg$username;
    if ( msg?$will_topic )
        info$will_topic = msg$will_topic;
    if ( first(fmt("mqtt|%s|%s", c$id$orig_h, msg$client_id)) )
        Log::write(MQTT_LOG, info);
    }

##! twigs passive discovery - DICOM and HL7 identity logs.
##!
##! Requires the compiled Spicy analyzers (medical.hlto) built from
##! dicom.spicy, hl7.spicy and medical.evt. Only association/header fields are
##! logged; no images, reports or patient data.

@load-sigs ./dpd.sig

module TwigsMedical;

export {
    redef enum Log::ID += { DICOM_LOG, HL7_LOG };

    ## Well-known ports. Other ports are found through the signatures in dpd.sig.
    const dicom_ports = { 104/tcp, 11112/tcp } &redef;
    const hl7_ports = { 2575/tcp } &redef;

    type DicomInfo: record {
        ts:                time   &log;
        uid:               string &log;
        requester:         addr   &log;   ##< sends A-ASSOCIATE-RQ (SCU, e.g. a modality)
        acceptor:          addr   &log;   ##< sends A-ASSOCIATE-AC (SCP, e.g. a PACS)
        acceptor_port:     port   &log;
        pdu:               string &log;   ##< "request" or "accept"
        sender:            addr   &log;   ##< host that sent this PDU
        calling_ae:        string &log;
        called_ae:         string &log;
        impl_class_uid:    string &log &optional;
        impl_version:      string &log &optional;
        abstract_syntaxes: vector of string &log &optional;
    };

    type Hl7Info: record {
        ts:                 time   &log;
        uid:                string &log;
        sender:             addr   &log;
        receiver:           addr   &log;
        server_port:        port   &log;
        sending_app:        string &log &optional;
        sending_facility:   string &log &optional;
        receiving_app:      string &log &optional;
        receiving_facility: string &log &optional;
        message_type:       string &log &optional;
        version:            string &log &optional;
    };
}

global seen: set[string] &create_expire=6 hrs;

event zeek_init() &priority=5
    {
    Log::create_stream(DICOM_LOG, [$columns=DicomInfo, $path="twigs_dicom"]);
    Log::create_stream(HL7_LOG, [$columns=Hl7Info, $path="twigs_hl7"]);
    # The analyzers come from a compiled Spicy module loaded at runtime, so
    # their tags are looked up by name rather than referenced directly.
    Analyzer::register_for_ports(Analyzer::get_tag("TwigsDICOM"), dicom_ports);
    Analyzer::register_for_ports(Analyzer::get_tag("TwigsHL7"), hl7_ports);
    }

function clean(s: string): string
    {
    # AE titles are space padded, UIDs may be NUL padded.
    return strip(gsub(s, /\x00/, ""));
    }

event TwigsDICOM::associate(c: connection, is_orig: bool, request: bool,
                            called_ae: string, calling_ae: string,
                            impl_class_uid: string, impl_version: string,
                            abstract_syntaxes: vector of string)
    {
    local info = DicomInfo($ts=network_time(), $uid=c$uid,
                           $requester=c$id$orig_h, $acceptor=c$id$resp_h,
                           $acceptor_port=c$id$resp_p,
                           $pdu=request ? "request" : "accept",
                           $sender=is_orig ? c$id$orig_h : c$id$resp_h,
                           $calling_ae=clean(calling_ae), $called_ae=clean(called_ae));
    if ( impl_class_uid != "" )
        info$impl_class_uid = clean(impl_class_uid);
    if ( impl_version != "" )
        info$impl_version = clean(impl_version);
    if ( |abstract_syntaxes| > 0 )
        {
        local syntaxes: vector of string = vector();
        for ( i in abstract_syntaxes )
            if ( i < 64 )
                syntaxes += clean(abstract_syntaxes[i]);
        info$abstract_syntaxes = syntaxes;
        }
    local key = fmt("dicom|%s|%s|%s|%s|%s", info$sender, info$pdu, info$calling_ae,
                    info$called_ae, info?$impl_version ? info$impl_version : "");
    if ( key in seen )
        return;
    add seen[key];
    Log::write(DICOM_LOG, info);
    }

function msh_field(fields: string_vec, idx: count): string
    {
    # fields[0] is "MSH", fields[1] is MSH-2, so MSH-n is fields[n-1].
    if ( idx - 1 >= |fields| )
        return "";
    return strip(gsub(fields[idx - 1], /\^+/, " "))[0:100];
    }

event TwigsHL7::message(c: connection, is_orig: bool, msh: string)
    {
    if ( |msh| < 4 )
        return;
    local fields = split_string(msh, string_to_pattern(fmt("\\%s", msh[3]), F));
    local info = Hl7Info($ts=network_time(), $uid=c$uid,
                         $sender=is_orig ? c$id$orig_h : c$id$resp_h,
                         $receiver=is_orig ? c$id$resp_h : c$id$orig_h,
                         $server_port=c$id$resp_p);
    local v = msh_field(fields, 3);
    if ( v != "" ) info$sending_app = v;
    v = msh_field(fields, 4);
    if ( v != "" ) info$sending_facility = v;
    v = msh_field(fields, 5);
    if ( v != "" ) info$receiving_app = v;
    v = msh_field(fields, 6);
    if ( v != "" ) info$receiving_facility = v;
    v = msh_field(fields, 9);
    if ( v != "" ) info$message_type = v;
    v = msh_field(fields, 12);
    if ( v != "" ) info$version = v;
    local key = fmt("hl7|%s|%s|%s|%s", info$sender,
                    info?$sending_app ? info$sending_app : "",
                    info?$sending_facility ? info$sending_facility : "",
                    info?$message_type ? info$message_type : "");
    if ( key in seen )
        return;
    add seen[key];
    Log::write(HL7_LOG, info);
    }

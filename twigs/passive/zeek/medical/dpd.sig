# Recognise DICOM and HL7/MLLP on any TCP port.

# DICOM A-ASSOCIATE-RQ: PDU type 0x01, reserved, 4-byte length, protocol version 1.
signature twigs-dicom-associate {
    ip-proto == tcp
    payload /^\x01\x00[\x00-\xff]{4}\x00\x01/
    tcp-state originator
    enable "TwigsDICOM"
}

# HL7 v2 over MLLP: <VT>MSH followed by the field separator.
signature twigs-hl7-mllp {
    ip-proto == tcp
    payload /^\x0bMSH[^\r]/
    enable "TwigsHL7"
}

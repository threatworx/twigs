local http = require "http"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local base64 = require "base64"

description = [[
Discovers information about network-connected CCTV cameras including manufacturer,
model, firmware version, and basic configuration details. Supports detection of:
- Arecont Vision cameras
- AXIS VAPIX cameras  
- HikVision cameras
- Samsung cameras

The script attempts to identify camera types through HTTP responses, headers,
and specific API endpoints commonly used by these manufacturers.
]]

author = "Security Assessment Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Rule to determine when script should run
portrule = shortport.port_or_service({80, 443, 554, 8000, 8001, 8080, 8081, 8083, 8888, 9000, 3702}, {"http", "https", "rtsp", "onvif"})

-- Camera detection patterns and endpoints
local camera_signatures = {
    ["Arecont Vision"] = {
        paths = {"/get", "/set?resolution", "/mjpeg.cgi", "/get?camera", "/get?date", "/get?network"},
        headers = {"server", "arecont"},
        patterns = {"ArecontVision", "Arecont Vision", "arecont%-vision"},
        info_endpoints = {
            "/get?camera",
            "/get?date", 
            "/get?network",
            "/get?system",
            "/get?video",
            "/get?audio",
            "/onvif/device_service"
        }
    },
    ["AXIS VAPIX"] = {
        paths = {"/axis-cgi/param.cgi", "/axis-cgi/mjpg/video.cgi", "/axis-cgi/view/info.cgi", "/axis-cgi/basicdeviceinfo.cgi"},
        headers = {"server", "axis"},
        patterns = {"AXIS", "axis", "vapix"},
        info_endpoints = {
            "/axis-cgi/param.cgi?action=list&group=Properties",
            "/axis-cgi/param.cgi?action=list&group=Brand",
            "/axis-cgi/param.cgi?action=list&group=Network",
            "/axis-cgi/basicdeviceinfo.cgi",
            "/axis-cgi/view/info.cgi",
            "/axis-cgi/admin/param.cgi?action=list&group=root.Properties",
            "/axis-cgi/serverreport.cgi",
            "/onvif/device_service"
        }
    },
    ["HikVision"] = {
        paths = {"/PSIA/capabilities", "/ISAPI/System/deviceInfo", "/onvif/device_service", "/ISAPI/Security/users"},
        headers = {"server", "hikvision"},
        patterns = {"Hikvision", "HIKVISION", "hikvision"},
        info_endpoints = {
            "/ISAPI/System/deviceInfo",
            "/ISAPI/System/capabilities",
            "/ISAPI/System/time",
            "/ISAPI/System/Network/interfaces",
            "/ISAPI/Streaming/channels",
            "/ISAPI/Security/users",
            "/PSIA/System/deviceInfo",
            "/PSIA/capabilities",
            "/System/configurationData"
        }
    },
    ["Samsung"] = {
        paths = {"/stw-cgi/system.cgi", "/samsungcam", "/cgi-bin/main-cgi", "/stw-cgi/video.cgi"},
        headers = {"server", "samsung"},
        patterns = {"Samsung", "SAMSUNG", "samsung"},
        info_endpoints = {
            "/stw-cgi/system.cgi?msubmenu=deviceinfo",
            "/stw-cgi/system.cgi?msubmenu=network",
            "/stw-cgi/video.cgi?msubmenu=videosource",
            "/cgi-bin/main-cgi?req_menu=device_info",
            "/stw-cgi/system.cgi?msubmenu=users",
            "/onvif/device_service"
        }
    }
}

-- Function to check RTSP service on port 554
local function check_rtsp_camera(host, port)
    if port.number ~= 554 then
        return nil
    end
    
    -- Send RTSP OPTIONS request
    local rtsp_request = "OPTIONS rtsp://" .. host.ip .. ":554 RTSP/1.0\r\n" ..
                        "CSeq: 1\r\n" ..
                        "User-Agent: NSE RTSP Scanner\r\n\r\n"
    
    local status, result = comm.exchange(host, port, rtsp_request, {timeout=5000})
    
    if status and result then
        local rtsp_info = {}
        
        -- Check for camera vendor in RTSP response
        local lower_result = string.lower(result)
        
        if string.find(lower_result, "hikvision") then
            rtsp_info.camera_type = "HikVision"
        elseif string.find(lower_result, "axis") then
            rtsp_info.camera_type = "AXIS VAPIX"
        elseif string.find(lower_result, "arecont") then
            rtsp_info.camera_type = "Arecont Vision"
        elseif string.find(lower_result, "samsung") then
            rtsp_info.camera_type = "Samsung"
        else
            rtsp_info.camera_type = "Generic RTSP Camera"
        end
        
        -- Extract server information
        local server = string.match(result, "Server:%s*([^\r\n]+)")
        if server then
            rtsp_info.server = server
        end
        
        -- Extract supported methods
        local public_methods = string.match(result, "Public:%s*([^\r\n]+)")
        if public_methods then
            rtsp_info.supported_methods = public_methods
        end
        
        rtsp_info.protocol = "RTSP"
        rtsp_info.port = 554
        
        return rtsp_info
    end
    
    return nil
end

-- Function to perform ONVIF device discovery and information extraction
local function perform_onvif_discovery(host, port)
    local onvif_info = {}
    
    -- ONVIF Device Service endpoints to try
    local onvif_endpoints = {
        "/onvif/device_service",
        "/onvif/Device",
        "/device_service",
        "/Device",
        "/onvif2/Device"
    }
    
    -- ONVIF GetDeviceInformation SOAP request
    local soap_request = [[<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetDeviceInformation/>
    </soap:Body>
</soap:Envelope>]]

    -- ONVIF GetCapabilities SOAP request
    local capabilities_request = [[<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetCapabilities>
            <tds:Category>All</tds:Category>
        </tds:GetCapabilities>
    </soap:Body>
</soap:Envelope>]]

    -- ONVIF GetSystemDateAndTime SOAP request
    local datetime_request = [[<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetSystemDateAndTime/>
    </soap:Body>
</soap:Envelope>]]

    for _, endpoint in ipairs(onvif_endpoints) do
        -- Try GetDeviceInformation
        local response = http.post(host, port, endpoint, {
            header = {
                ["Content-Type"] = "application/soap+xml; charset=utf-8",
                ["SOAPAction"] = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
            }
        }, soap_request)
        
        if response and response.status == 200 and response.body then
            onvif_info.onvif_enabled = true
            onvif_info.onvif_endpoint = endpoint
            
            -- Extract device information from SOAP response
            local manufacturer = string.match(response.body, "<tds:Manufacturer>([^<]+)</tds:Manufacturer>")
            local model = string.match(response.body, "<tds:Model>([^<]+)</tds:Model>")
            local firmware = string.match(response.body, "<tds:FirmwareVersion>([^<]+)</tds:FirmwareVersion>")
            local serial = string.match(response.body, "<tds:SerialNumber>([^<]+)</tds:SerialNumber>")
            local hardware = string.match(response.body, "<tds:HardwareId>([^<]+)</tds:HardwareId>")
            
            if manufacturer then onvif_info.onvif_manufacturer = manufacturer end
            if model then onvif_info.onvif_model = model end
            if firmware then onvif_info.onvif_firmware = firmware end
            if serial then onvif_info.onvif_serial = serial end
            if hardware then onvif_info.onvif_hardware_id = hardware end
            
            -- Try GetCapabilities
            local cap_response = http.post(host, port, endpoint, {
                header = {
                    ["Content-Type"] = "application/soap+xml; charset=utf-8",
                    ["SOAPAction"] = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"
                }
            }, capabilities_request)
            
            if cap_response and cap_response.status == 200 and cap_response.body then
                -- Extract capabilities
                local analytics = string.match(cap_response.body, "<tt:Analytics[^>]*>")
                local device_io = string.match(cap_response.body, "<tt:DeviceIO[^>]*>")
                local events = string.match(cap_response.body, "<tt:Events[^>]*>")
                local imaging = string.match(cap_response.body, "<tt:Imaging[^>]*>")
                local media = string.match(cap_response.body, "<tt:Media[^>]*>")
                local ptz = string.match(cap_response.body, "<tt:PTZ[^>]*>")
                
                local capabilities = {}
                if analytics then table.insert(capabilities, "Analytics") end
                if device_io then table.insert(capabilities, "DeviceIO") end
                if events then table.insert(capabilities, "Events") end
                if imaging then table.insert(capabilities, "Imaging") end
                if media then table.insert(capabilities, "Media") end
                if ptz then table.insert(capabilities, "PTZ") end
                
                if #capabilities > 0 then
                    onvif_info.onvif_capabilities = table.concat(capabilities, ", ")
                end
                
                -- Extract service URLs
                local media_url = string.match(cap_response.body, '<tt:Media.-XAddr>([^<]+)</tt:XAddr>')
                local ptz_url = string.match(cap_response.body, '<tt:PTZ.-XAddr>([^<]+)</tt:XAddr>')
                local events_url = string.match(cap_response.body, '<tt:Events.-XAddr>([^<]+)</tt:XAddr>')
                
                if media_url then onvif_info.onvif_media_service = media_url end
                if ptz_url then onvif_info.onvif_ptz_service = ptz_url end
                if events_url then onvif_info.onvif_events_service = events_url end
            end
            
            -- Try GetSystemDateAndTime
            local dt_response = http.post(host, port, endpoint, {
                header = {
                    ["Content-Type"] = "application/soap+xml; charset=utf-8",
                    ["SOAPAction"] = "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"
                }
            }, datetime_request)
            
            if dt_response and dt_response.status == 200 and dt_response.body then
                local timezone = string.match(dt_response.body, "<tt:TimeZone>([^<]+)</tt:TimeZone>")
                local utc_time = string.match(dt_response.body, "<tt:UTCDateTime.-</tt:UTCDateTime>")
                local dst = string.match(dt_response.body, "<tt:DaylightSavings>([^<]+)</tt:DaylightSavings>")
                
                if timezone then onvif_info.onvif_timezone = timezone end
                if dst then onvif_info.onvif_dst = dst end
            end
            
            break -- Found working ONVIF endpoint, no need to try others
        end
    end
    
    return onvif_info
end

-- Function to perform WS-Discovery for ONVIF devices (UDP port 3702)
local function perform_ws_discovery(host)
    local ws_discovery_info = {}
    
    -- WS-Discovery Probe message for ONVIF devices
    local probe_message = [[<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:tdn="http://www.onvif.org/ver10/network/wsdl">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>urn:uuid:12345678-1234-1234-1234-123456789012</wsa:MessageID>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <wsd:Probe>
            <wsd:Types>tdn:NetworkVideoTransmitter</wsd:Types>
        </wsd:Probe>
    </soap:Body>
</soap:Envelope>]]
    
    -- Note: WS-Discovery typically uses UDP multicast on port 3702
    -- For simplicity in NSE, we'll focus on HTTP-based ONVIF discovery
    -- A full implementation would require UDP socket handling
    
    return ws_discovery_info
end

-- Function to check HTTP response for camera signatures
local function check_camera_type(host, port, response, headers)
    -- Check WWW-Authenticate header first (like "Basic realm=\"Arecont Vision\"")
    if headers and headers["www-authenticate"] then
        local auth_header = string.lower(headers["www-authenticate"])
        if string.find(auth_header, "arecont") then
            return "Arecont Vision"
        elseif string.find(auth_header, "axis") then
            return "AXIS VAPIX"
        elseif string.find(auth_header, "hikvision") then
            return "HikVision"
        elseif string.find(auth_header, "samsung") then
            return "Samsung"
        end
    end
    
    for camera_type, sig in pairs(camera_signatures) do
        -- Check headers
        for _, header_name in ipairs(sig.headers) do
            local header_value = headers[header_name]
            if header_value then
                for _, pattern in ipairs(sig.patterns) do
                    if string.find(string.lower(header_value), string.lower(pattern)) then
                        return camera_type
                    end
                end
            end
        end
        
        -- Check response body
        if response and response.body then
            for _, pattern in ipairs(sig.patterns) do
                if string.find(response.body, pattern) then
                    return camera_type
                end
            end
        end
    end
    return nil
end

-- Function to extract detailed camera information based on type
local function extract_detailed_camera_info(host, port, camera_type)
    local info = {}
    local sig = camera_signatures[camera_type]
    
    if not sig or not sig.info_endpoints then
        return info
    end
    
    -- Try each information endpoint for the detected camera type
    for _, path in ipairs(sig.info_endpoints) do
        local response = http.get(host, port, path)
        if response and response.status == 200 and response.body then
            info.accessible_endpoints = info.accessible_endpoints or {}
            table.insert(info.accessible_endpoints, path)
            
            -- Extract specific information based on camera type
            if camera_type == "AXIS VAPIX" then
                -- Extract comprehensive AXIS information
                if string.find(path, "basicdeviceinfo") then
                    info.model = string.match(response.body, "ProdNbr=([^%s&]+)") or info.model
                    info.serial_number = string.match(response.body, "SerialNumber=([^%s&]+)") or info.serial_number
                    info.architecture = string.match(response.body, "Architecture=([^%s&]+)") or info.architecture
                end
                
                if string.find(path, "param.cgi") then
                    info.brand = string.match(response.body, "Brand=([^%s&]+)") or info.brand
                    info.hardware_id = string.match(response.body, "HardwareID=([^%s&]+)") or info.hardware_id
                    info.firmware = string.match(response.body, "Version=([^%s&]+)") or info.firmware
                    info.build_date = string.match(response.body, "BuildDate=([^%s&]+)") or info.build_date
                    info.soc = string.match(response.body, "Soc=([^%s&]+)") or info.soc
                    
                    -- Network information
                    info.hostname = string.match(response.body, "HostName=([^%s&]+)") or info.hostname
                    info.dhcp = string.match(response.body, "DHCP=([^%s&]+)") or info.dhcp
                end
                
            elseif camera_type == "HikVision" then
                -- Extract comprehensive HikVision information
                if string.find(path, "deviceInfo") then
                    info.device_name = string.match(response.body, "<deviceName>([^<]+)</deviceName>") or info.device_name
                    info.model = string.match(response.body, "<model>([^<]+)</model>") or info.model
                    info.serial_number = string.match(response.body, "<serialNumber>([^<]+)</serialNumber>") or info.serial_number
                    info.firmware = string.match(response.body, "<firmwareVersion>([^<]+)</firmwareVersion>") or info.firmware
                    info.mac_address = string.match(response.body, "<macAddress>([^<]+)</macAddress>") or info.mac_address
                    info.device_type = string.match(response.body, "<deviceType>([^<]+)</deviceType>") or info.device_type
                    info.encoder_version = string.match(response.body, "<encoderVersion>([^<]+)</encoderVersion>") or info.encoder_version
                end
                
                if string.find(path, "capabilities") then
                    -- Extract capability information
                    local video_caps = string.match(response.body, "<VideoInput.-</VideoInput>")
                    if video_caps then
                        info.video_inputs = string.match(video_caps, 'videoInputPortNums="([^"]+)"') or info.video_inputs
                    end
                end
                
                if string.find(path, "Network") then
                    info.ip_address = string.match(response.body, "<ipAddress>([^<]+)</ipAddress>") or info.ip_address
                    info.subnet_mask = string.match(response.body, "<subnetMask>([^<]+)</subnetMask>") or info.subnet_mask
                    info.gateway = string.match(response.body, "<defaultGateway>([^<]+)</defaultGateway>") or info.gateway
                end
                
            elseif camera_type == "Arecont Vision" then
                -- Extract comprehensive Arecont information
                if string.find(path, "camera") then
                    info.model = string.match(response.body, "camera=([^%s&]+)") or info.model
                    info.serial_number = string.match(response.body, "serialnumber=([^%s&]+)") or info.serial_number
                    info.firmware = string.match(response.body, "version=([^%s&]+)") or info.firmware
                    info.build_date = string.match(response.body, "builddate=([^%s&]+)") or info.build_date
                end
                
                if string.find(path, "network") then
                    info.ip_address = string.match(response.body, "ipaddress=([^%s&]+)") or info.ip_address
                    info.subnet_mask = string.match(response.body, "subnetmask=([^%s&]+)") or info.subnet_mask
                    info.gateway = string.match(response.body, "gateway=([^%s&]+)") or info.gateway
                    info.mac_address = string.match(response.body, "macaddress=([^%s&]+)") or info.mac_address
                    info.dhcp = string.match(response.body, "dhcp=([^%s&]+)") or info.dhcp
                end
                
                if string.find(path, "video") then
                    info.resolution = string.match(response.body, "resolution=([^%s&]+)") or info.resolution
                    info.framerate = string.match(response.body, "framerate=([^%s&]+)") or info.framerate
                    info.compression = string.match(response.body, "compression=([^%s&]+)") or info.compression
                end
                
                if string.find(path, "system") then
                    info.uptime = string.match(response.body, "uptime=([^%s&]+)") or info.uptime
                    info.temperature = string.match(response.body, "temperature=([^%s&]+)") or info.temperature
                end
                
            elseif camera_type == "Samsung" then
                -- Extract Samsung information
                if string.find(path, "deviceinfo") then
                    info.model = string.match(response.body, "Model=([^%s&]+)") or info.model
                    info.serial_number = string.match(response.body, "Serial=([^%s&]+)") or info.serial_number
                    info.firmware = string.match(response.body, "Firmware=([^%s&]+)") or info.firmware
                    info.mac_address = string.match(response.body, "MAC=([^%s&]+)") or info.mac_address
                end
                
                if string.find(path, "network") then
                    info.ip_address = string.match(response.body, "IP=([^%s&]+)") or info.ip_address
                    info.subnet_mask = string.match(response.body, "Subnet=([^%s&]+)") or info.subnet_mask
                    info.gateway = string.match(response.body, "Gateway=([^%s&]+)") or info.gateway
                end
                
                if string.find(path, "videosource") then
                    info.video_standard = string.match(response.body, "Standard=([^%s&]+)") or info.video_standard
                    info.resolution = string.match(response.body, "Resolution=([^%s&]+)") or info.resolution
                end
            end
            
            -- Check for ONVIF support regardless of camera type
            if string.find(path, "onvif") then
                info.onvif_supported = true
            end
        elseif response and response.status == 401 then
            -- Authentication required, but endpoint exists
            info.protected_endpoints = info.protected_endpoints or {}
            table.insert(info.protected_endpoints, path)
        end
    end
    
    -- Always try ONVIF discovery regardless of camera type detection
    local onvif_data = perform_onvif_discovery(host, port)
    for key, value in pairs(onvif_data) do
        info[key] = value
    end
    
    return info
end

-- Function to check for additional security issues and configurations
local function perform_security_assessment(host, port, camera_type)
    local security_info = {}
    
    -- Check for common vulnerable endpoints
    local vuln_endpoints = {
        "/system.ini",
        "/config/config.dat", 
        "/cgi-bin/guest/Audio.cgi",
        "/tmpfs/auto.jpg",
        "/cgi-bin/nobody/Machine.cgi",
        "/HNAP1/",
        "/goform/",
        "/.htaccess",
        "/backup.tar",
        "/system.xml"
    }
    
    security_info.vulnerable_endpoints = {}
    for _, endpoint in ipairs(vuln_endpoints) do
        local response = http.get(host, port, endpoint)
        if response and response.status == 200 then
            table.insert(security_info.vulnerable_endpoints, endpoint)
        end
    end
    
    -- Check for directory traversal
    local traversal_paths = {
        "/../../../../etc/passwd",
        "/../../../etc/shadow",
        "/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    }
    
    for _, path in ipairs(traversal_paths) do
        local response = http.get(host, port, path)
        if response and response.status == 200 and 
           (string.find(response.body, "root:") or string.find(response.body, "localhost")) then
            security_info.directory_traversal = true
            break
        end
    end
    
    -- Check SSL/TLS configuration if HTTPS
    if port.number == 443 then
        security_info.https_enabled = true
        -- Additional SSL checks could be added here
    end
    
    -- Check for weak authentication
    local response = http.get(host, port, "/")
    if response then
        if not response.header["www-authenticate"] then
            security_info.no_authentication = true
        else
            local auth_header = response.header["www-authenticate"]
            if string.find(string.lower(auth_header), "basic") then
                security_info.basic_auth_only = true
                security_info.auth_realm = string.match(auth_header, 'realm="([^"]*)"')
            end
        end
    end
    
    return security_info
end

-- Function to check for common default credentials
local function check_default_auth(host, port)
    local common_creds = {
        -- Arecont Vision common defaults
        {"admin", "admin"},
        {"admin", ""},
        {"viewer", "viewer"},
        {"user", "user"},
        -- General camera defaults
        {"admin", "password"},
        {"admin", "12345"},
        {"root", "root"},
        {"admin", "1234"},
        {"admin", "admin123"}
    }
    
    local auth_results = {}
    
    for _, cred in ipairs(common_creds) do
        local username, password = cred[1], cred[2]
        local response = http.get(host, port, "/", {
            auth = {username = username, password = password}
        })
        
        if response and (response.status == 200 or response.status == 302) then
            table.insert(auth_results, username .. ":" .. (password == "" and "<blank>" or password))
            break -- Stop after first successful auth to avoid account lockouts
        end
    end
    
    return auth_results
end

-- Main action function
action = function(host, port)
    local output = stdnse.output_table()
    
    -- Check if this is RTSP port 554
    if port.number == 554 then
        local rtsp_info = check_rtsp_camera(host, port)
        if rtsp_info then
            for key, value in pairs(rtsp_info) do
                output[key] = value
            end
            output.note = "RTSP streaming service detected - use RTSP client to view streams"
            return output
        else
            return "Port 554 open but no RTSP response detected"
        end
    end
    
    -- For HTTP ports, continue with existing logic
    local response = http.get(host, port, "/")
    if not response then
        return "Failed to connect to HTTP service"
    end
    
    -- Check for camera type
    local camera_type = check_camera_type(host, port, response, response.header)
    
    if not camera_type then
        -- Try some common camera paths if initial detection failed
        local common_paths = {"/", "/index.html", "/live", "/viewer", "/view"}
        for _, path in ipairs(common_paths) do
            local test_response = http.get(host, port, path)
            if test_response then
                camera_type = check_camera_type(host, port, test_response, test_response.header)
                if camera_type then break end
            end
        end
    end
    
    if camera_type then
        output.camera_type = camera_type
        
        -- Extract detailed information
        local camera_info = extract_detailed_camera_info(host, port, camera_type)
        for key, value in pairs(camera_info) do
            output[key] = value
        end
        
        -- Perform comprehensive security assessment
        local security_assessment = perform_security_assessment(host, port, camera_type)
        for key, value in pairs(security_assessment) do
            output[key] = value
        end
        
        -- Check for default credentials (only if camera type is detected)
        local default_creds = check_default_auth(host, port)
        if #default_creds > 0 then
            output.default_credentials = default_creds
            output.security_warning = "CRITICAL: Default credentials detected - change immediately!"
        end
        
        -- Compile security warnings
        local warnings = {}
        if output.default_credentials then
            table.insert(warnings, "Default credentials found")
        end
        if output.no_authentication then
            table.insert(warnings, "No authentication required")
        end
        if output.basic_auth_only then
            table.insert(warnings, "Only basic authentication (unencrypted)")
        end
        if output.vulnerable_endpoints and #output.vulnerable_endpoints > 0 then
            table.insert(warnings, "Vulnerable endpoints exposed")
        end
        if output.directory_traversal then
            table.insert(warnings, "Directory traversal vulnerability")
        end
        if port.number ~= 443 and not output.https_enabled then
            table.insert(warnings, "Unencrypted HTTP connection")
        end
        if output.onvif_enabled and output.basic_auth_only then
            table.insert(warnings, "ONVIF services with weak authentication")
        end
        
        if #warnings > 0 then
            output.security_warnings = warnings
            output.risk_level = "HIGH"
        else
            output.risk_level = "LOW"
        end
        
    else
        output.status = "No supported camera type detected"
        output.note = "Device may not be a supported CCTV camera or may be using non-standard configuration"
    end
    
    return output
end


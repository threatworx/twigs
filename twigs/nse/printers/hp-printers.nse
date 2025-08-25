description = [[
Identifies HP printers using SNMP, HTTP(S), and JetDirect (PJL).
Extracts make/model information for reliable identification.
]]

---
-- @usage
-- nmap -p 161,80,443,9100 --script hp-printers <target>
--
-- @output
-- | hp-printers:
-- |   Make: HP
-- |   Model: HP LaserJet Pro M404dn
--

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local comm = require "comm"
local snmp = require "snmp"

portrule = function(host, port)
    -- Run if any of these ports are open
    return port.number == 161 or port.number == 80 or port.number == 443 or port.number == 9100
end

-- SNMP
local function try_snmp(host)
    local ok, session = snmp.Helper:new(host, {number = 161, protocol = "udp"}, "public")
    if not ok or not session then return nil end

    local sysDescrOID = "1.3.6.1.2.1.1.1.0"
    local hpModelOID  = "1.3.6.1.2.1.43.5.1.1.16.1"

    local sysDescr = session:get(sysDescrOID)
    local model = session:get(hpModelOID)

    if sysDescr and sysDescr.value and sysDescr.value:match("HP") then
	model = model.value or sysDescr.value
        return model
    end
    return nil
end

-- HTTP(S)
local function try_http(host, port)
    local paths = { "/hp/device/DeviceInformation.xml", "/hp/device/this.LCDispatcher?nav=hp.DeviceInfo" }
    for _, path in ipairs(paths) do
        local ok, response = http.get(host, port, path)
        if ok and response and response.body then
            -- Try <ProductName> first
            local model = response.body:match("<ProductName>(.-)</ProductName>")
            if not model then
                -- Fallback: first <dd> (used on older printer UIs)
                model = response.body:match("<dd>(.-)</dd>")
            end
            if model then
		model = model:match("^%s*(.-)%s*$")
	        model = model:gsub("^@PJL INFO ID%s*\"?", ""):gsub("\"?$", ""):gsub("[\r\n]", "")
                return model
            end
        end
    end
    return nil
end

-- JetDirect (PJL)
local function try_jetdirect(host)
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok, err = socket:connect(host, 9100)
    if not ok then return nil end
    socket:send("\027%-12345X@PJL INFO ID\r\n")
    local status, response = socket:receive_lines(1)
    socket:close()

    if status and response and response:match("HP") then
	response = response:match("^%s*(.-)%s*$")
	response = response:gsub("^@PJL INFO ID%s*\"?", ""):gsub("\"?$", ""):gsub("[\r\n]", "")
        return response
    end
    return nil
end

-- Combined action: try all protocols
action = function(host, port)
    -- 1. SNMP first
    local snmp_data = try_snmp(host)
    if snmp_data then
        result = stdnse.output_table()
        result["hp printer"] = snmp_data 
        return result
    end

    -- 2. HTTP & HTTPS
    for _, p in ipairs({80, 443}) do
        local http_data = try_http(host, {number=p, protocol=(p==443 and "https" or "http")})
        if http_data then
            result = stdnse.output_table()
            result["hp printer"] = http_data 
            return result
        end
    end

    -- 3. JetDirect
    local jet_data = try_jetdirect(host)
    if jet_data then
        result = stdnse.output_table()
        result["hp printer"] = jet_data 
        return result
    end

    return nil
end


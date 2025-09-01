local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Discovers Arecont Vision camera devices on the network by analyzing HTTP response headers.
The script sends a simple HTTP request and checks for the characteristic "Arecont Vision"
realm in the WWW-Authenticate header that these cameras return.
]]

---
-- @usage
-- nmap --script arecont-discovery -p80,8080 <target>
-- nmap --script arecont-discovery --script-args http-max-cache-size=0 -p80,8080 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | arecont-discovery: 
-- |_  Arecont Vision
--
-- @args arecont-discovery.path The path to request. Default: "/"
-- @args arecont-discovery.timeout HTTP timeout. Default: 10s
--

author = "Security Researcher"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Rule to determine when this script should run
portrule = shortport.http

-- Main action function
action = function(host, port)
    local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
    local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 10000
    
    -- Configure HTTP options
    local options = {
        timeout = timeout,
        header = {
            ["User-Agent"] = "Mozilla/5.0 (compatible; Nmap NSE)"
        }
    }
    
    -- Send HTTP GET request
    local response = http.get(host, port, path, options)
    
    if not response then
        stdnse.debug1("No HTTP response received")
        return nil
    end
    
    -- Check if we got a response with headers
    if not response.header then
        stdnse.debug1("No headers in HTTP response")
        return nil
    end
    
    -- Look for WWW-Authenticate header containing "Arecont Vision"
    local www_auth = response.header["www-authenticate"]
    if www_auth then
        stdnse.debug2("WWW-Authenticate header: " .. www_auth)
        
        -- Check if the header contains "Arecont Vision"
        if string.find(www_auth:lower(), "arecont vision") then
            return "Arecont Vision"
        end
    end
    
    -- Also check for case where multiple WWW-Authenticate headers exist
    -- Some HTTP libraries store multiple headers as a table
    if type(www_auth) == "table" then
        for _, auth_header in ipairs(www_auth) do
            if string.find(auth_header:lower(), "arecont vision") then
                return "Arecont Vision"
            end
        end
    end
    
    -- Check all headers for any mention of Arecont Vision (fallback)
    for header_name, header_value in pairs(response.header) do
        if type(header_value) == "string" and 
           string.find(header_value:lower(), "arecont vision") then
            stdnse.debug2("Found Arecont Vision in header: " .. header_name)
            return "Arecont Vision"
        end
    end
    
    stdnse.debug1("No Arecont Vision signature found in response headers")
    return nil
end

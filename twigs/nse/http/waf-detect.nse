local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Detects the presence of a web application firewall (WAF) and identifies its type.
Inspects HTTP response headers, cookies, and body for known WAF fingerprints across
cloud WAFs (Cloudflare, AWS WAF, Azure, Akamai Kona, Sucuri, DDoS-Guard), commercial
WAFs (F5 BigIP/ASM, Fortinet FortiWeb, Imperva/Incapsula, Barracuda, Radware AppWall,
Citrix Netscaler), open-source WAFs (ModSecurity, Naxsi), and bot-detection platforms
(PerimeterX, DataDome, Reblaze, Wallarm, Signal Sciences).

Intensive mode sends additional attack-like payloads to trigger WAF block pages,
enabling detection of WAFs that only reveal themselves when blocking.
]]

---
-- @args waf-detect.root  Base path for requests. Defaults to <code>/</code>.
-- @args waf-detect.intensive  If set, sends attack-like probes to trigger block pages.
--
-- @usage
-- nmap --script=waf-detect <target>
-- nmap --script=waf-detect --script-args waf-detect.intensive=1 <target>
--
-- @output
-- 80/tcp open http
-- | waf-detect:
-- |   waf: Cloudflare
-- |_  waf: ModSecurity

author = "ThreatWorx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- case-insensitive header lookup (nmap stores headers lowercase already)
local function get_header(response, name)
  if not response or not response.header then return nil end
  return response.header[name:lower()]
end

-- check if any response cookie name matches a Lua pattern
local function has_cookie(response, pattern)
  if not response or not response.cookies then return false end
  for _, cookie in pairs(response.cookies) do
    if cookie.name and string.find(cookie.name, pattern) then return true end
  end
  return false
end

-- case-insensitive body substring search
local function body_has(response, text)
  if not response or not response.body then return false end
  return string.find(response.body:lower(), text:lower(), 1, true) ~= nil
end

-- WAF definitions: each entry has name, match(responses)->bool, intensive(host,port,root)->bool
local wafs = {}

-- Cloudflare
wafs[#wafs+1] = {
  name = "Cloudflare",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "cf-ray") or get_header(r, "cf-cache-status") or
         get_header(r, "cf-mitigated") then
        return true
      end
      if r.header and r.header.server and
         (r.header.server == "cloudflare" or r.header.server == "cloudflare-nginx") then
        return true
      end
      if has_cookie(r, "^__cfduid$") or has_cookie(r, "^__cf_bm$") or
         has_cookie(r, "^cf_clearance$") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=<script>alert(1)</script>")
    if r and r.status == 403 and body_has(r, "cloudflare") then return true end
    return false
  end,
}

-- AWS WAF / Shield Advanced
wafs[#wafs+1] = {
  name = "AWS WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^aws%-waf%-token$") then return true end
      if body_has(r, "aws waf") then return true end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and (body_has(r, "aws waf") or body_has(r, "request blocked")) then
      return true
    end
    return false
  end,
}

-- Azure Application Gateway WAF / Azure Front Door WAF
wafs[#wafs+1] = {
  name = "Azure WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-azure-ref") then return true end
      if get_header(r, "x-ms-asm-requestid") then return true end
      if body_has(r, "microsoft azure application gateway") then return true end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>"))
    if r and r.status == 403 and body_has(r, "azure") then return true end
    return false
  end,
}

-- Akamai Kona Site Defender / Bot Manager
wafs[#wafs+1] = {
  name = "Akamai Kona",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-check-cacheable") or get_header(r, "akamai-grn") or
         get_header(r, "x-akamai-ssl-client-sid") then
        return true
      end
      if has_cookie(r, "^ak_bmsc$") or has_cookie(r, "^bm_sz$") then return true end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and body_has(r, "reference #") and body_has(r, "access denied") then
      return true
    end
    return false
  end,
}

-- Sucuri Firewall / CloudProxy
wafs[#wafs+1] = {
  name = "Sucuri Firewall",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-sucuri-id") or get_header(r, "x-sucuri-cache") then return true end
      if r.header and r.header.server and string.find(r.header.server:lower(), "sucuri") then
        return true
      end
      if body_has(r, "sucuri website firewall") or body_has(r, "sucuri cloudproxy") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>"))
    if r and r.status == 403 and body_has(r, "sucuri") then return true end
    return false
  end,
}

-- Imperva SecureSphere / Incapsula
wafs[#wafs+1] = {
  name = "Imperva Incapsula",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^incap_ses") or has_cookie(r, "^visid_incap") or
         has_cookie(r, "^reese84$") then
        return true
      end
      if get_header(r, "x-iinfo") then return true end
      if body_has(r, "incapsula incident") or body_has(r, "powered by imperva") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and (body_has(r, "incapsula") or body_has(r, "imperva")) then
      return true
    end
    return false
  end,
}

-- Fortinet FortiWeb
wafs[#wafs+1] = {
  name = "Fortinet FortiWeb",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server and
         string.find(r.header.server:lower(), "fortiweb") then
        return true
      end
      if has_cookie(r, "^FORTIWAFSID$") then return true end
      if body_has(r, "fortiweb") or body_has(r, "fortigate") then return true end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and body_has(r, "fortiweb") then return true end
    return false
  end,
}

-- Radware AppWall
wafs[#wafs+1] = {
  name = "Radware AppWall",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-sl-compstate") then return true end
      if has_cookie(r, "^rdwr_id$") or has_cookie(r, "^RDWR") then return true end
      if body_has(r, "radware appwall") or
         body_has(r, "unauthorized activity has been detected") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- F5 BigIP LTM / ASM
wafs[#wafs+1] = {
  name = "F5 BigIP",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-cnection") then return true end
      if r.header and r.header.server == "BigIP" then return true end
      if has_cookie(r, "^BIGipServer") then return true end
      -- F5 ASM sets cookies like TS + 4-6 alphanumerics
      for _, cookie in pairs(r.cookies or {}) do
        if cookie.name and string.match(cookie.name, "^TS%w%w%w%w%w?%w?$") then
          return true
        end
      end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and body_has(r, "the requested url was rejected") then
      return true
    end
    return false
  end,
}

-- F5 Traffic Shield
wafs[#wafs+1] = {
  name = "F5 Traffic Shield",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server == "F5-TrafficShield" then return true end
      if has_cookie(r, "^ASINFO$") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Barracuda WAF
wafs[#wafs+1] = {
  name = "Barracuda WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^barra_counter_session$") then return true end
      if get_header(r, "x-barracuda-waf-request-id") or
         get_header(r, "x-barracuda-ref") then
        return true
      end
      if body_has(r, "barracuda networks") then return true end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and body_has(r, "barracuda") then return true end
    return false
  end,
}

-- Citrix Netscaler / Citrix ADC
wafs[#wafs+1] = {
  name = "Citrix Netscaler",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.via and string.find(r.header.via, "NS%-CACHE") then
        return true
      end
      if r.header and (r.header.cneonction == "close" or r.header.nncoection == "close") then
        return true
      end
      if get_header(r, "x-client-ip") then return true end
      if has_cookie(r, "^ns_af$") or has_cookie(r, "^citrix_ns_id$") or
         has_cookie(r, "^NSC_") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Teros / Citrix Application Firewall Enterprise
wafs[#wafs+1] = {
  name = "Teros WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^st8id$") or has_cookie(r, "^st8_wat$") or
         has_cookie(r, "^st8_wlf$") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- ModSecurity (Apache / Nginx)
wafs[#wafs+1] = {
  name = "ModSecurity",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server then
        local sv = r.header.server
        if string.find(sv, "mod_security") or string.find(sv, "Mod_Security") then
          return true
        end
        if sv == "NOYB" then return true end
      end
      if get_header(r, "x-modsec-score") then return true end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("<script>alert(1)</script>"))
    if r and r.status == 403 and
       (body_has(r, "modsecurity") or body_has(r, "mod_security") or
        body_has(r, "not acceptable")) then
      return true
    end
    return false
  end,
}

-- Naxsi (nginx module)
wafs[#wafs+1] = {
  name = "Naxsi",
  match = function(responses) return false end,
  intensive = function(host, port, root)
    -- Naxsi only blocks score-based patterns; benign bracket vs stacked brackets differ
    local r1 = http.get(host, port, root .. "?a=[")
    local r2 = http.get(host, port, root .. "?a=[[[]]]][[[]")
    if r1 and r2 and r1.status ~= r2.status then return true end
    return false
  end,
}

-- Webknight (IIS)
wafs[#wafs+1] = {
  name = "Webknight",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server and
         string.find(r.header.server, "WebKnight/") then
        return true
      end
      if r.status == 999 then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- BinarySec
wafs[#wafs+1] = {
  name = "BinarySec",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server and
         string.find(r.header.server, "BinarySEC/") then
        return true
      end
      if get_header(r, "x-binarysec-via") or get_header(r, "x-binarysec-nocache") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- dotDefender (Applicure)
wafs[#wafs+1] = {
  name = "dotDefender",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-dotdefender-denied") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- IBM DataPower Gateway
wafs[#wafs+1] = {
  name = "IBM DataPower",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-backside-transport") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Profense WAF
wafs[#wafs+1] = {
  name = "Profense",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server == "Profense" then return true end
      if has_cookie(r, "^PLBSID$") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Airlock WAF (Ergon)
wafs[#wafs+1] = {
  name = "Airlock WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      for _, cookie in pairs(r.cookies or {}) do
        if cookie.name == "AL_LB" and cookie.value and
           string.sub(cookie.value, 1, 4) == "$xc/" then
          return true
        end
        if cookie.name == "AL_SESS" and cookie.value and
           (string.sub(cookie.value, 1, 5) == "AAABL" or
            string.sub(cookie.value, 1, 5) == "LgEAA") then
          return true
        end
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Barracuda / DenyAll rWeb
wafs[#wafs+1] = {
  name = "DenyAll rWeb",
  match = function(responses)
    for _, r in pairs(responses) do
      -- sessioncookie is the DenyAll rWeb indicator; low confidence on its own
      if has_cookie(r, "^sessioncookie$") then
        if body_has(r, "denyall") or body_has(r, "rweb") then return true end
      end
      if body_has(r, "denyall web application firewall") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- USP Secure Entry Server
wafs[#wafs+1] = {
  name = "USP Secure Entry Server",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server == "Secure Entry Server" then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Cisco ACE XML Gateway
wafs[#wafs+1] = {
  name = "Cisco ACE XML Gateway",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server == "ACE XML Gateway" then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Microsoft ISA Server / Forefront TMG
wafs[#wafs+1] = {
  name = "Microsoft ISA Server",
  match = function(responses)
    for _, r in pairs(responses) do
      if body_has(r, "isa server denied") or
         body_has(r, "the isa server denied the specified") or
         body_has(r, "forefront threat management gateway") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- DDoS-Guard
wafs[#wafs+1] = {
  name = "DDoS-Guard",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^__ddg") then return true end
      if body_has(r, "ddos-guard") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- PerimeterX Bot Defender
wafs[#wafs+1] = {
  name = "PerimeterX",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^_pxhd$") or has_cookie(r, "^_pxvid$") or
         has_cookie(r, "^_px3$") or has_cookie(r, "^_px$") then
        return true
      end
      if body_has(r, "perimeterx") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- DataDome Bot Protection
wafs[#wafs+1] = {
  name = "DataDome",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^datadome$") then return true end
      if get_header(r, "x-datadome-cid") then return true end
      if body_has(r, "datadome") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Reblaze WAF
wafs[#wafs+1] = {
  name = "Reblaze",
  match = function(responses)
    for _, r in pairs(responses) do
      if has_cookie(r, "^rbzid$") then return true end
      if get_header(r, "x-reblaze-protection") then return true end
      if body_has(r, "reblaze") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Wallarm WAF
wafs[#wafs+1] = {
  name = "Wallarm WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-wallarm-node-info") or
         get_header(r, "x-wallarm-upstream-response-time") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root)
    local r = http.get(host, port, root .. "?x=" .. url.escape("' OR 1=1--"))
    if r and r.status == 403 and body_has(r, "wallarm") then return true end
    return false
  end,
}

-- Signal Sciences / Fastly Next-Gen WAF
wafs[#wafs+1] = {
  name = "Signal Sciences WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-sigsci-requestid") or get_header(r, "x-sigsci-tags") then
        return true
      end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Alibaba Cloud WAF (Aliyun)
wafs[#wafs+1] = {
  name = "Alibaba Cloud WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "eagleid") or get_header(r, "ali-cdn-real-ip") then return true end
      if body_has(r, "errors.aliyun.com") or body_has(r, "alibaba cloud") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- NSFocus WAF
wafs[#wafs+1] = {
  name = "NSFocus WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server and
         string.find(r.header.server, "NSFocus") then
        return true
      end
      if body_has(r, "nsfocus") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- Comodo WAF / cWatch
wafs[#wafs+1] = {
  name = "Comodo WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if r.header and r.header.server and
         string.find(r.header.server:lower(), "comodo waf") then
        return true
      end
      if body_has(r, "comodo waf") or body_has(r, "protected by comodo") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

-- AppTrana WAF (Indusface)
wafs[#wafs+1] = {
  name = "AppTrana WAF",
  match = function(responses)
    for _, r in pairs(responses) do
      if get_header(r, "x-indf-requestid") then return true end
      if body_has(r, "apptrana") or body_has(r, "indusface") then return true end
    end
    return false
  end,
  intensive = function(host, port, root) return false end,
}

local function send_requests(host, port, root)
  local requests = {}
  local all = {}
  local responses = {}

  -- benign requests
  all = http.pipeline_add(root, nil, all, "GET")
  table.insert(requests, "normal")

  all = http.pipeline_add(root .. "asofKlj404", nil, all, "GET")
  table.insert(requests, "nonexistent")

  all = http.pipeline_add(root, nil, all, "ASDE")
  table.insert(requests, "invalidmethod")

  -- attack-like probes for passive fingerprinting
  all = http.pipeline_add(root .. "?x=" .. url.escape("../../../etc/passwd"), nil, all, "GET")
  table.insert(requests, "traversal")

  all = http.pipeline_add(root .. "?x=" .. url.escape("<script>alert(1)</script>"), nil, all, "GET")
  table.insert(requests, "xss")

  all = http.pipeline_add(root .. "?x=" .. url.escape("' OR 1=1--"), nil, all, "GET")
  table.insert(requests, "sqli")

  all = http.pipeline_add(root .. "?x=cmd.exe", nil, all, "GET")
  table.insert(requests, "cmdexe")

  all = http.pipeline_add(root .. "?x=" .. url.escape("${jndi:ldap://x.x/a}"), nil, all, "GET")
  table.insert(requests, "log4j")

  local pipeline_responses = http.pipeline_go(host, port, all)
  if not pipeline_responses then
    stdnse.debug1("No pipeline response from %s", host.ip)
    return nil
  end

  for i, response in pairs(pipeline_responses) do
    if requests[i] then
      responses[requests[i]] = response
    end
  end
  return responses
end

action = function(host, port)
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"
  local intensive = stdnse.get_script_args(SCRIPT_NAME .. ".intensive")

  local responses = send_requests(host, port, root)
  if not responses then return nil end

  local detected = {}
  for _, waf in ipairs(wafs) do
    local found = waf.match(responses)
    if not found and intensive then
      found = waf.intensive(host, port, root)
    end
    if found then
      table.insert(detected, waf.name)
    end
  end

  if #detected > 0 then
    local lines = {}
    for _, name in ipairs(detected) do
      table.insert(lines, "waf: " .. name)
    end
    return table.concat(lines, "\n")
  end
end

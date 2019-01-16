local JSON = require "kong.plugins.middleman.json"
local url = require "socket.url"

local string_format = string.format

local kong = kong
local kong_response = kong.response

local get_method = ngx.req.get_method
local ngx_re_find = ngx.re.find
local ngx_set_header = ngx.req.set_header
local pairs = pairs

local HTTP = "http"
local HTTPS = "https"

local _M = {}

function JSON.assert(_is_valid, message)
  ngx.log(ngx.ERR, "[middleman] failed to parse json: ", message)
end

local function parse_url(host_url)
  local parsed_url = url.parse(host_url)
  if not parsed_url.port then
    if parsed_url.scheme == HTTP then
      parsed_url.port = 80
     elseif parsed_url.scheme == HTTPS then
      parsed_url.port = 443
     end
  end
  if not parsed_url.path then
    parsed_url.path = "/"
  end
  return parsed_url
end

function _M.execute(conf)
  if not conf.run_on_preflight and get_method() == "OPTIONS" then
    return
  end

  local name = "[middleman] "
  local ok, err
  local parsed_url = parse_url(conf.url)
  local host = parsed_url.host
  local port = tonumber(parsed_url.port)
  local payload = _M.compose_payload(parsed_url)

  local sock = ngx.socket.tcp()
  sock:settimeout(conf.timeout)

  ok, err = sock:connect(host, port)
  if not ok then
    ngx.log(ngx.ERR, name .. "failed to connect to " .. host .. ":" .. tostring(port) .. ": ", err)
    return kong_response.exit(500, "internal error")
  end

  if parsed_url.scheme == HTTPS then
    local _, err = sock:sslhandshake(true, host, false)
    if err then
      ngx.log(ngx.ERR, name .. "failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", err)
      return kong_response.exit(500, "internal error")
    end
  end

  ok, err = sock:send(payload)
  if not ok then
    ngx.log(ngx.ERR, name .. "failed to send data to " .. host .. ":" .. tostring(port) .. ": ", err)
    return kong_response.exit(500, "internal error")
  end

  local line, err = sock:receive("*l")
  if err then 
    ngx.log(ngx.ERR, name .. "failed to read response status from " .. host .. ":" .. tostring(port) .. ": ", err)
    return kong_response.exit(500, "internal error")
  end

  local status_code = tonumber(string.match(line, "%s(%d%d%d)%s"))
  if status_code > 399 then
    local error_message = "internal error"
    if status_code == 401 then
      error_message = "unauthorized"
    end
    return kong_response.exit(status_code, error_message)
  end

  repeat
    line, err = sock:receive("*l")
    if err then
      ngx.log(ngx.ERR, name .. "failed to read header " .. host .. ":" .. tostring(port) .. ": ", err)
      return kong_response.exit(500, "internal error")
    end
  until ngx_re_find(line, "^\\s*$", "jo")

  local body = {}
  repeat
    line, err = sock:receive("*l")
    if err then
      ngx.log(ngx.ERR, name .. "failed to read body " .. host .. ":" .. tostring(port) .. ": ", err)
      return kong_response.exit(500, "internal error")
    end

    local raw_body = string.match(line, "%b{}")
    if raw_body then
      body, err = JSON:decode(raw_body)
      if err then
        ngx.log(ngx.ERR, name .. "failed to parse body " .. host .. ":" .. tostring(port) .. ": ", err)
        return kong_response.exit(500, "internal error")
      end
    end
  until ngx_re_find(line, "^\\s*$", "jo")

  ok, err = sock:setkeepalive(conf.keepalive)
  if not ok then
    ngx.log(ngx.ERR, name .. "failed to keepalive to " .. host .. ":" .. tostring(port) .. ": ", err)
    return kong_response.exit(500, "internal error")
  end

  for key, value in pairs(body) do
    ngx_set_header("X-Introspection-" .. key, value)
  end
end

function _M.compose_payload(introspection_details)
    local request_uri_args = kong.request.get_query()
    local request_body = kong.request.get_body()

    local request_params = kong.table.merge(request_uri_args, request_body)
    local utoken = request_params["utoken"]
    if not utoken then
      utoken = request_params["token"]
    end

    local introspection_url = introspection_details.path
    if utoken then
      introspection_url = introspection_url .. "?utoken=" .. utoken
    end

    return string_format(
      "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
      introspection_url, introspection_details.host)
end

return _M

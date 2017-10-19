local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Retrieves modulus from server's SSL certificate.
]]

author = "Graa"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

local function output_str(cert)
  local rsaModulus = {}

  if cert.pubkey.type == "rsa" then
    rsaModulus[#rsaModulus+ 1] = openssl.bignum_bn2dec(cert.pubkey.modulus)
  end

  return stdnse.strjoin("\n", rsaModulus)
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    return
  end

  return output_str(cert)
end

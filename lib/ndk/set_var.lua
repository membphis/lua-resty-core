-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require 'ffi'
local base = require "resty.core.base"
local ffi_string = ffi.string
local C = ffi.C

local c_buf_type = ffi.typeof("char[?]")
local ffi_new = ffi.new

local _M = { version = base.version }


ffi.cdef[[
unsigned int ngx_http_lua_ffi_set_misc_escape_pgsql_str(unsigned char *dst,
    const unsigned char *src, size_t size);
unsigned int ngx_http_lua_ffi_pg_utf_escape(unsigned char *dst,
    const unsigned char *str, size_t size);
]]


local escape_pgsql_str = C.ngx_http_lua_ffi_set_misc_escape_pgsql_str
local pg_utf_escape = C.ngx_http_lua_ffi_pg_utf_escape


local get_sql_buf, get_sql_utf_buf

do
    local buf_size = 128
    local buf = ffi_new(c_buf_type, buf_size)

function get_sql_buf(len)
    if len > buf_size then
        while len > buf_size do
            buf_size = buf_size * 2
        end

        buf = ffi_new(c_buf_type, len)
    end

    return buf
end

end -- do


do
    local buf_size = 128
    local buf = ffi_new(c_buf_type, buf_size)

function get_sql_utf_buf(len)
    if len > buf_size then
        while len > buf_size do
            buf_size = buf_size * 2
        end

        buf = ffi_new(c_buf_type, len)
    end

    return buf
end

end -- do


function _M.quote_pgsql_str(str)
    if not str or str == '' then
        return "''"
    end

    local str_len = #str
    local sql_len = escape_pgsql_str(nil, str, str_len)
    local sql_buf = get_sql_buf(sql_len)

    escape_pgsql_str(sql_buf, str, str_len)

    local sql_utf_len = pg_utf_escape(nil, sql_buf, sql_len)
    if sql_utf_len == sql_len then
        return ffi_string(sql_buf, sql_len)
    end

    local sql_buf_utf = get_sql_utf_buf(sql_utf_len)
    sql_utf_len = pg_utf_escape(sql_buf_utf, sql_buf, sql_len)

    return ffi_string(sql_buf_utf, sql_utf_len)
end

local str = "\x83\x04\x03\x43\x02\x72\x30\x33";
print(_M.quote_pgsql_str(str))
print(ndk.set_var.set_quote_pgsql_str(str))

return _M

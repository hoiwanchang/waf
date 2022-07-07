--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    log_record('White_IP',ngx.var_request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    log_record('BlackList_IP',ngx.var_request_uri,"_","_")
                    if config_waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local ATTACK_URI=ngx.var.uri
        local CLIENT_IP = get_client_ip()
        if CLIENT_IP ~= nil and ATTACK_URI ~= nil then
            local CC_TOKEN = get_client_ip()..ATTACK_URI
        else
            local CC_TOKEN = "tokens-for-illgale-requests"
        end
        local limit = ngx.shared.limit
        local CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        local CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        local REQ_ARGS, err = ngx.req.get_uri_args()

        if err == "truncated" then
            ngx.exit(403)
        end  

        if REQ_ARGS ~= nil then
            for _,rule in pairs(ARGS_RULES) do
                for key, val in pairs(REQ_ARGS) do
                    if type(val) == 'table' then
                        local ARGS_DATA = table.concat(val, " ")
                    else
                        local ARGS_DATA = val
                    end
                    if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                        log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                        if config_waf_enable == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end
    end
    return false
end

--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post
function post_attack_check()
    if config_post_check == "on" and ngx.req.get_method() == "POST" then
        local READ_BODY = ngx.req.read_body()
        local POST_RULES = get_rule('post.rule')
	local POST_ARGS, err = ngx.req.get_post_args()

        if err == "truncated" then
            ngx.exit(403)
        end
       
        if POST_ARGS ~= nil then
            for _,rule in pairs(POST_RULES) do

                for key, val in pairs(POST_ARGS) do

                    if type(key) == 'table' then
                        local ARGS_DATA = table.concat(key, " ")
                    else
                        local ARGS_DATA = key
                    end
                    if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                        log_record('Deny_Post_Args',ngx.var.request_uri,"-",rule)
                        if config_waf_enable == "on" then
                            waf_output()
                            return true
                        end
                    end
                    -- post data got 2 diff forms, check value too. 
                    if type(val) == 'table' then
                        local ARGS_DATA = table.concat(val, " ")
                    else
                        local ARGS_DATA = val
                    end
                    if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                        log_record('Deny_Post_Args',ngx.var.request_uri,"-",rule)
                        if config_waf_enable == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end
    end
    return false
end

--deny header
function header_attack_check()
    if config_header_check == "on" then
        local HEADER_RULES = get_rule('header.rule')
        local HEADERS, err = ngx.req.get_headers()

        if err == "truncated" then
            ngx.exit(403)
        end

        if HEADERS ~= nil then
            for _,rule in pairs(HEADER_RULES) do
                for key, val in pairs(HEADERS) do
                    if type(val) == 'table' then
                        local HEADER_DATA = table.concat(val, " ")
                    else
                        local HEADER_DATA = val
                    end
                    if HEADER_DATA and type(HEADER_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(HEADER_DATA),rule,"jo") then
                        log_record('Deny_Header_Injects',ngx.var.request_uri,"-",rule)
                        if config_waf_enable == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end

    end
    return false
end

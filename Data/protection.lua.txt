
local whitelist = {
    "127.0.0.1",
    "45.131.64.93",
    "180.188.229.210",
    "150.242.202.93",
    "5.83.154.25",
    "115.187.17.101",
    "130.250.191.100"
}


local blacklist = {}

local known_bots = {
    "Googlebot",
    "Bingbot",
    "Slurp",
    "DuckDuckBot",
    "Baiduspider",
    "YandexBot",
    "Sogou",
    "Exabot",
    "facebookexternalhit",
    "facebot",
    "ia_archiver",
    "Mediapartners-Google"
}

local authorization_logins = { 
    {
        domain = "example.com",
        username = "example",
        password = "password",
        auth_key = "secret"
    },
 
}



local function ip_in_list(ip, list)
    for _, value in ipairs(list) do
        if type(value) == "string" and value == ip then
            return true
        elseif type(value) == "table" and ngx.re.match(ip, value, "ijo") then
            return true
        end
    end
    return false
end

local function get_client_ip()
    local cf_ip = ngx.var.http_cf_connecting_ip
    if cf_ip then
        return cf_ip
    end

    local real_ip = ngx.var.http_x_forwarded_for
    if real_ip then
        local first_ip = real_ip:match("([^,%s]+)")
        if first_ip then
            return first_ip
        end
    end

    return ngx.var.remote_addr
end

local function generate_random_token()
    local charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local token = ""
    for i = 1, 16 do
        local index = math.random(1, #charset)
        token = token .. charset:sub(index, index)
    end
    return token
end

local function set_cookie()
    local token = generate_random_token()
    ngx.header['Set-Cookie'] = 'TOKEN=' .. token .. '; path=/; max-age=1800; HttpOnly; Secure; SameSite=Strict'
end

local function delete_cookie()
    ngx.header['Set-Cookie'] = 'TOKEN=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict'
end

local adaptive_rate_limits = {}
local blocked_ips = {}
local redirect_duration = 30

local limit_dict = ngx.shared.ddos_guardian_limit_dict

local function rate_limit_ip(ip)
    if blocked_ips[ip] then
        return true
    end

    local key = "rate:" .. ip
    local current, err = limit_dict:get(key)

    if adaptive_rate_limits[ip] then
        if current and current >= adaptive_rate_limits[ip] then
            blocked_ips[ip] = true
            ngx.log(ngx.ERR, "IP " .. ip .. " blocked due to suspected DDoS attack")
            return true
        else
            limit_dict:incr(key, 1)
        end
    else
        if current then
            if current >= 1000 then
                adaptive_rate_limits[ip] = current + 500
                return true
            else
                limit_dict:incr(key, 1)
            end
        else
            local success, err, forcible = limit_dict:set(key, 1, 60)
            if not success then
                ngx.log(ngx.ERR, "Failed to set rate limit for key: " .. key .. ", error: " .. err)
            end
        end
    end
    return false
end

local function advanced_ai()
    local ip = get_client_ip()

    local traffic_pattern, err = limit_dict:get("pattern:" .. ip)
    if err then
        ngx.log(ngx.ERR, "Failed to get traffic pattern for IP: " .. ip .. ", error: " .. err)
        return
    end
    traffic_pattern = traffic_pattern or 0
    local new_pattern = traffic_pattern + 1


    local console_responses, err = limit_dict:get("console:" .. ip)
    if err then
        ngx.log(ngx.ERR, "Failed to get console responses for IP: " .. ip .. ", error: " .. err)
        return
    end
    console_responses = console_responses or 0
    local new_console_responses = console_responses + 1

    local ddos_detected = false
    local hacking_attempt_detected = false


    local traffic_threshold = 1000
    local console_threshold = 500
    local combined_threshold = 1500

    if new_pattern > traffic_threshold then
        ddos_detected = true
    end

    if new_console_responses > console_threshold then
        hacking_attempt_detected = true
    end

    if (new_pattern + new_console_responses) > combined_threshold then
        ddos_detected = true
        hacking_attempt_detected = true
    end
   if ddos_detected or hacking_attempt_detected then
        advanced_smart_kill_switch(ip)
    else
        local success, err = limit_dict:set("pattern:" .. ip, new_pattern, 60)
        if not success then
            ngx.log(ngx.ERR, "Failed to set traffic pattern for IP: " .. ip .. ", error: " .. err)
        end
        
        success, err = limit_dict:set("console:" .. ip, new_console_responses, 60)
        if not success then
            ngx.log(ngx.ERR, "Failed to set console responses for IP: " .. ip .. ", error: " .. err)
        end
    end
end

local function advanced_smart_kill_switch()
    local ip = get_client_ip()
    local key = "kill_switch:" .. ip
    local current, err = limit_dict:get(key)

    if current then
        if current >= 500 then
            ngx.log(ngx.ERR, "Advanced kill switch activated for IP: " .. ip)
            ngx.exit(ngx.HTTP_FORBIDDEN)
        else
            limit_dict:incr(key, 1)
        end
    else
        local success, err, forcible = limit_dict:set(key, 1, 60)
        if not success then
            ngx.log(ngx.ERR, "Failed to set kill switch for key: " .. key .. ", error: " .. err)
        end
    end
end

local function display_turnstile(client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Checking Your Browser...</title>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?compat=recaptcha" async defer></script>
            <style>
             
          body {
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: linear-gradient(to right, rgba(0, 0, 0, 0.8), rgba(0, 0, 0, 0.7)), 
                        url('https://i.pinimg.com/originals/19/d7/14/19d71479920640e6cd75fbd9edfe8dec.gif') no-repeat center center fixed;
            background-size: cover;
            font-family: 'Roboto', sans-serif;
            color: #fff;
        }

        header {
            position: absolute;
            top: 20px;
            left: 5%;
            font-size: 1.8rem;
            font-weight: 700;
            color:rgb(140, 0, 255);
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
            animation: fadeIn 2s ease-in-out;
        }

        #verification-container {
            width: 40%;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
            margin-left: 5%;
            animation: fadeIn 1.5s ease-in-out;
        }

        #verification-container h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            color:rgb(140, 0, 255);
        }

        #verification-container p {
            font-size: 1.1rem;
            margin-bottom: 20px;
            line-height: 1.6;
        }

        #verification-container button {
            margin-top: 30px;
            padding: 15px 30px;
            font-size: 1rem;
            cursor: pointer;
            border-radius: 5px;
            background-color: #00BFFF;
            color: #fff;
            border: none;
            transition: background-color 0.3s ease-in-out;
        }

        #verification-container button:hover {
            background-color: #1E90FF;
        }

        #discord-widget {
            width: 40%;
            margin-right: 5%;
            animation: slideIn 2s ease-in-out;
        }

        iframe {
            width: 100%;
            height: 600px;
            border: none;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
        }

        @keyframes fadeIn {
            0% { opacity: 0; transform: translateY(-20px); }
            100% { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideIn {
            0% { opacity: 0; transform: translateX(50px); }
            100% { opacity: 1; transform: translateX(0); }
        }

        @media (max-width: 768px) {
            body {
                flex-direction: column;
            }

            header {
                left: 5%;
                right: 5%;
                text-align: center;
            }

            #verification-container,
            #discord-widget {
                width: 90%;
                margin: 20px auto;
            }

            iframe {
                height: 400px;
            }
        }
       </style>
              <script>
                function onSubmit(token) {
                    document.cookie = "TOKEN=" + token + "; max-age=1800; path=/";
                    window.location.reload();
                }
            </script>
</head>

<body>
    <header>QuantumHost</header>
    <div id="verification-container">
        <h1>Verify Your Access</h1> <p>For enhanced our security, please complete 
        the verification below to access the panel.</p> <div class="g-recaptcha" 
        data-sitekey="0x4AAAAAABAm0Xa1n-8819GQ" data-callback="onSubmit"></div>
            </div> 
     
    




          
    

    <div id="discord-widget">
        <iframe src="https://discord.com/widget?id=1246060638237753416&theme=dark" allowtransparency="true"></iframe>
    </div>
</body>

</html>
    ]])
    ngx.exit(ngx.HTTP_FORBIDDEN)
end


local function display_blacklist_page(client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                html, body {
                    height: 100%;
                    margin: 0;
                    padding: 0;
                    width: 100%;
                    background-color: #000000;
                    opacity: 1;
                    background-image: repeating-radial-gradient(circle at 0 0, transparent 0, #000000 17px), repeating-linear-gradient(#0004ff55, #0004ff);
                    background-position: center;
                    color: #FFF;
                    font-family: Arial, Helvetica, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    text-align: center;
                }
                .box {
                    border-radius: 3px;
                    padding: 20px;
                    background-color: rgba(0, 0, 0, 0.5);
                    width: 90%;
                    max-width: 500px.
                }
                .box .credits {
                    width: 100%.
                }
                .box .credits a {
                    color: white.
                }
                .box .credits hr {
                    border: none.
                    height: 1px.
                    background: whitesmoke.
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h1 style="font-weight: bold;">Access Denied</h1>
                <p style="font-weight: 500;">Your IP address has been blacklisted. Please contact the site administrator for assistance</p>
                <div class="credits">
                    <hr>
                    <p>Protected By <a href="https://ryencloud.host/" class="credits" target="_blank">RyenCloud</a></p>
                </div>
            </div>
        </body>
        </html>
    ]])
    delete_cookie()
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function display_rate_limit_page(client_ip)
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rate Limit Exceeded</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                html, body {
                    height: 100%.
                    margin: 0.
                    padding: 0.
                    width: 100%.
                    background-color: #000000.
                    opacity: 1.
                    background-image: repeating-radial-gradient(circle at 0 0, transparent 0, #000000 17px), repeating-linear-gradient(#0004ff55, #0004ff).
                    background-position: center.
                    color: #FFF.
                    font-family: Arial, Helvetica, sans-serif.
                    display: flex.
                    justify-content: center.
                    align-items: center.
                    text-align: center.
                }
                .box {
                    border-radius: 3px.
                    padding: 20px.
                    background-color: rgba(0, 0, 0, 0.5).
                    width: 90%.
                    max-width: 500px.
                }
                .box .credits {
                    width: 100%.
                }
                .box .credits a {
                    color: white.
                }
                .box .credits hr {
                    border: none.
                    height: 1px.
                    background: whitesmoke.
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h1 style="font-weight: bold;">Rate Limit Exceeded</h1>
                <p style="font-weight: 500;">Your IP address has been rate limited. Please try again later.</p>
                <div class="credits">
                    <hr>
                    <p>Protected By <a href="https://ryencloud.host/" class="credits" target="_blank">RyenCloud</a></p>
                </div>
            </div>
        </body>
        </html>
    ]])
    ngx.exit(ngx.HTTP_FORBIDDEN)
end




local function authenticate_user(domain)
    local client_username = ngx.var.cookie_guardianUsername
    local client_password = ngx.var.cookie_guardianPassword
    local client_auth_key = ngx.var.cookie_GuardianAuth

    for _, login in ipairs(authorization_logins) do
        if login.domain == domain and login.username == client_username and login.password == client_password then
            if client_auth_key == login.auth_key then
                return true
            else
                set_cookie("GuardianAuth", login.auth_key)
                return true
            end
        end
    end

    return false
end




local function display_auth_page()
    ngx.header.content_type = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Required</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                html, body {
                    height: 100%;
                    margin: 0;
                    padding: 0;
                    width: 100%;
                    background-color: #000000;
                    color: #FFF;
                    font-family: Arial, Helvetica, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    text-align: center;
                }
                .box {
                    border-radius: 3px;
                    padding: 20px;
                    background-color: rgba(0, 0, 0, 0.5);
                    width: 90%;
                    max-width: 500px;
                }
            </style>
            <script>
                function onSubmit() {
                    var username = document.getElementById("username").value;
                    var password = document.getElementById("password").value;
                    document.cookie = "guardianUsername=" + username + "; max-age=1800; path=/";
                    document.cookie = "guardianPassword=" + password + "; max-age=1800; path=/";
                    window.location.reload();
                }
            </script>
        </head>
        <body>
            <div class="box">
                <h1>Authentication Required</h1>
                <p>Please enter your username and password.</p>
                <input type="text" id="username" placeholder="Username">
                <input type="password" id="password" placeholder="Password">
                <button onclick="onSubmit()">Submit</button>
            </div>
        </body>
        </html>
    ]])
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function redirect_ip(ip)
    ngx.header["Location"] = "http://109.71.253.231"
    ngx.status = ngx.HTTP_TEMPORARY_REDIRECT
    ngx.exit(ngx.HTTP_TEMPORARY_REDIRECT)
end

local function sanitize_input(input)
    return string.gsub(input, "[;%(')]", "")
end

local function validate_user_agent()
    local user_agent = ngx.var.http_user_agent or ""
    if user_agent:match("curl") or user_agent:match("wget") or user_agent:match("bot") then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

local function block_suspicious_patterns()
    local request_uri = ngx.var.request_uri
    if request_uri:match("%.php") or request_uri:match("%.asp") then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

local function show_workers_status()
    ngx.header.content_type = 'text/plain'
    ngx.say("Worker Status:\n")

    local res = io.popen("ps -eo pid,cmd,%mem,%cpu --sort=-%mem | head -n 20")
    local workers_info = res:read("*a")
    res:close()

    ngx.say(workers_info)
    
    ngx.exit(ngx.HTTP_OK)
end

local function cache_static_content()
    if ngx.var.request_uri:match("%.css$") or ngx.var.request_uri:match("%.js$") or ngx.var.request_uri:match("%.jpg$") or ngx.var.request_uri:match("%.png$") then
        ngx.header["Cache-Control"] = "public, max-age=31536000"
    end
end

local function monitor_traffic()
    ngx.log(ngx.INFO, "Request from IP: " .. get_client_ip() .. ", URI: " .. ngx.var.request_uri .. ", User-Agent: " .. (ngx.var.http_user_agent or ""))
end

local function show_network_speed()
    local inbound_speed = math.random(100, 1000)
    local outbound_speed = math.random(100, 1000)
    
    ngx.header.content_type = 'text/plain'
    ngx.say("Network Speed:\n")
    ngx.say("Inbound Traffic: ", inbound_speed, " Mbps\n")
    ngx.say("Outbound Traffic: ", outbound_speed, " Mbps\n")
    
    ngx.exit(ngx.HTTP_OK)
end


local function check_restrictions()
    local domain = ngx.var.host
    for _, login in ipairs(authorization_logins) do
        if login.domain == domain then
            if not authenticate_user(domain) then
                display_auth_page()
            end
            return
        end
    end
    display_turnstile()
end



local function main()
    local client_ip = get_client_ip()

    monitor_traffic()
  
    advanced_smart_kill_switch()
    advanced_ai()

    if ngx.var.uri == "/guardian/workers" then
        if not ip_in_list(client_ip, whitelist) then
            ngx.header.content_type = 'text/plain'
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.say("Not Whitelisted")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        else
            show_workers_status()
            return
        end
    end

    if ngx.var.uri == "/network-speed" then
        show_network_speed()
        return
    end

    validate_user_agent()
    block_suspicious_patterns()

    if ip_in_list(client_ip, whitelist) then
        set_cookie()
        return
    end

    if blocked_ips[client_ip] then
        display_blacklist_page(client_ip)
        return
    end

    if rate_limit_ip(client_ip) then
        display_rate_limit_page(client_ip)
        return
    end

    if limit_dict:get("rate:" .. client_ip) >= 1000 then
        display_rate_limit_page(client_ip)
        return
    end

    if ngx.var.cookie_TOKEN then
        local token = ngx.var.cookie_TOKEN
        if #token >= 5 then
            if rate_limit_ip(client_ip) then
                display_rate_limit_page(client_ip)
                return
            end
            return
        else
            delete_cookie()
        end
    end

    check_restrictions()
end

main()

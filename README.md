# Flexa Shield Layer 7 DDoS Protection. 
Layer 7 DDoS Protection is a robust solution designed to protect your server from Layer 7 (application layer) DDoS attacks. This tool leverages Nginx for filtering and protecting your web applications.
# Features. 
Protects against Layer 7 DDoS attacks
Whitelisting IPs for trusted access
Easy installation and configuration
Lightweight and efficient
# Installation. 
Follow the steps below to install Flexa Shield Layer 7 DDoS Protection on your server:
# Step 1: Install the service. 
Mkdir -p /etc/nginx/flexa-shield-ly-7
```cd /etc/nginx/flexa-shield-ly-7
```
# Edit
Now, use nano protect.lua and edit it to your likings. DO NOT REMOVE CREDITS

Right under. 
```local whitelist = {
    "127.0.0.1",
    "109.71.253.231",
}```
White list, your IP's. For your services to bypass the captcha, for
# EXAMPLE.
# How to configure?
White list, your IP's. For your services to bypass the captcha, for # EXAMPLE. 
You, can edit the files in nginx.conf
lua_shared_dict secure_shield_limit_dict 10m;
server {


location / {
```lua_shared_dict shared.ddos_flexa_limit_dict 10m;
server {


location / {
access_by_lua_file /etc/nginx/flexa-shield-ly-7/protect.lua;```

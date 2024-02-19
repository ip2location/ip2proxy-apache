# IP2Proxy HTTP Module for Apache

The module detects visitor IP addresses which are used as VPN anonymizer, open proxies, web proxies, Tor exit nodes, search engine robots, data center ranges, residential proxies, consumer privacy networks, and enterprise private networks.

A IP2Proxy database is required for the lookup. It can be downloaded from https://lite.ip2location.com (Free) or https://www.ip2location.com (Commercial).



### Installation

1. Create a working directory.

   ```
   mkdir ~/ip2proxy-dev
   cd ~/ip2proxy-dev
   ```

   ​

2. Download IP2Proxy C library source code.

   ```
   git clone https://github.com/ip2location/ip2proxy-c.git
   ```

   ​

3. Compile and install the IP2Proxy C library.

   ```
   cd ip2proxy-c
   autoreconf -i -v --force
   ./configure
   make
   make install
   ```

   ​

4. Refresh local library.

   ```
   ldconfig
   ```

   ​

5. Download IP2Proxy Apache module.

   ```
   cd ~/ip2proxy-dev
   git clone https://github.com/ip2location/ip2proxy-apache
   cd ip2proxy-apache
   ```

   ​

6. Compile IP2Proxy module.

   ```
   apxs2 -i -a -L /usr/local/lib/ -I ../ip2proxy-c/libIP2Proxy/ -l IP2Proxy -c mod_ip2proxy.c
   ```



### Configuration

```
<IfModule mod_ip2proxy.c>
	IP2ProxyEnable <On|Off>
	# ENV will set server variables
	# NOTES will set apache notes
	# ALL will set both
	IP2ProxySetmode <ALL|ENV|NOTES>
	IP2ProxyDBFile <PATH_TO_IP2PROXY_BINARY_DATABASE>
	IP2ProxyDetectProxy <On|Off>
</IfModule>
```




/* Copyright (C) 2005-2017 IP2Proxy.com
 * All Rights Reserved
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h" 
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "IP2Proxy.h"

static const int ENV_SET_MODE	= 0x0001;
static const int NOTES_SET_MODE	= 0x0002;
static const int ALL_SET_MODE	= 0x0003;

typedef struct {
	int enabled;
	int detectReverseProxy;
	int setMode; 
	char* dbFile;
	IP2Proxy* ip2proxyObj;
} ip2proxy_server_config;

module AP_MODULE_DECLARE_DATA IP2Proxy_module;

static apr_status_t ip2proxy_cleanup(void *cfgdata) {
	return APR_SUCCESS;
}

static void ip2proxy_child_init(apr_pool_t *p, server_rec *s) {
	apr_pool_cleanup_register(p, NULL, ip2proxy_cleanup, ip2proxy_cleanup);
}

static int ip2proxy_post_read_request(request_rec *r) {
	char* ipaddr;
	ip2proxy_server_config* config;
	IP2ProxyRecord* record;
	char buff[20];
	
	config = (ip2proxy_server_config*) ap_get_module_config(r->server->module_config, &IP2Proxy_module);
	
	if(!config->enabled)
		return OK;

	if(config->detectReverseProxy){
		if(apr_table_get(r->headers_in, "Client-IP")) {
			ipaddr = (char *)apr_table_get(r->headers_in, "Client-IP");
		}
		else if(apr_table_get(r->headers_in, "X-Forwarded-For")) {
			ipaddr = (char *)apr_table_get(r->headers_in, "X-Forwarded-For");
		}
		else if(apr_table_get(r->headers_in, "X-Forwarded-IP")) {
			ipaddr = (char *)apr_table_get(r->headers_in, "X-Forwarded-IP");
		}
		else if(apr_table_get(r->headers_in, "Forwarded-For")) {
			ipaddr = (char *)apr_table_get(r->headers_in, "Forwarded-For");
		}
		else if(apr_table_get(r->headers_in, "X-Forwarded")) {
			ipaddr = (char *)apr_table_get(r->headers_in, "X-Forwarded");
		}
		else if(apr_table_get(r->headers_in, "Via")) {
			ipaddr = (char *)apr_table_get(r->headers_in, "Via");
		}
		else {
			#if (((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER >= 4)) || (AP_SERVER_MAJORVERSION_NUMBER > 2))
				ipaddr = r->connection->client_ip;
			#else
				ipaddr = r->connection->remote_ip;
			#endif
		}
	}
	else{
		#if (((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER >= 4)) || (AP_SERVER_MAJORVERSION_NUMBER > 2))
			ipaddr = r->connection->client_ip;
		#else	
			ipaddr = r->connection->remote_ip;
		#endif	
	}

	record = IP2Proxy_get_all(config->ip2proxyObj, ipaddr);

	if(record) {
		if(config->setMode & ENV_SET_MODE) {
			apr_table_set(r->subprocess_env, "IP2PROXY_COUNTRY_SHORT", record->country_short); 
			apr_table_set(r->subprocess_env, "IP2PROXY_COUNTRY_LONG", record->country_long); 
			apr_table_set(r->subprocess_env, "IP2PROXY_REGION", record->region); 
			apr_table_set(r->subprocess_env, "IP2PROXY_CITY", record->city); 
			apr_table_set(r->subprocess_env, "IP2PROXY_ISP", record->isp); 
			apr_table_set(r->subprocess_env, "IP2PROXY_IS_PROXY", record->is_proxy);
			apr_table_set(r->subprocess_env, "IP2PROXY_PROXY_TYPE", record->proxy_type);
			apr_table_set(r->subprocess_env, "IP2PROXY_DOMAIN", record->domain);
			apr_table_set(r->subprocess_env, "IP2PROXY_USAGE_TYPE", record->usage_type);
			apr_table_set(r->subprocess_env, "IP2PROXY_ASN", record->asn);
			apr_table_set(r->subprocess_env, "IP2PROXY_AS", record->as_);
			apr_table_set(r->subprocess_env, "IP2PROXY_LAST_SEEN", record->last_seen);
			apr_table_set(r->subprocess_env, "IP2PROXY_THREAT", record->threat);
		}
		if(config->setMode & NOTES_SET_MODE) {
			apr_table_set(r->notes, "IP2PROXY_COUNTRY_SHORT", record->country_short); 
			apr_table_set(r->notes, "IP2PROXY_COUNTRY_LONG", record->country_long); 
			apr_table_set(r->notes, "IP2PROXY_REGION", record->region); 
			apr_table_set(r->notes, "IP2PROXY_CITY", record->city); 
			apr_table_set(r->notes, "IP2PROXY_ISP", record->isp); 
			apr_table_set(r->notes, "IP2PROXY_IS_PROXY", record->is_proxy); 
			apr_table_set(r->notes, "IP2PROXY_PROXY_TYPE", record->proxy_type); 
			apr_table_set(r->notes, "IP2PROXY_DOMAIN", record->domain);
			apr_table_set(r->notes, "IP2PROXY_USAGE_TYPE", record->usage_type);
			apr_table_set(r->notes, "IP2PROXY_ASN", record->asn);
			apr_table_set(r->notes, "IP2PROXY_AS", record->as_);
			apr_table_set(r->notes, "IP2PROXY_LAST_SEEN", record->last_seen);
			apr_table_set(r->notes, "IP2PROXY_THREAT", record->threat);
		}
	
		IP2Proxy_free_record(record);		
	}
	
	return OK;
}

static const char* set_ip2proxy_enable(cmd_parms *cmd, void *dummy, int arg) {
	ip2proxy_server_config* config = (ip2proxy_server_config*) ap_get_module_config(cmd->server->module_config, &IP2Proxy_module);
	
	if(!config) 
		return NULL;
	
	config->enabled = arg;
	
	return NULL;
}

static const char* set_ip2proxy_dbfile(cmd_parms* cmd, void* dummy, const char* dbFile, int arg) {
	ip2proxy_server_config* config = (ip2proxy_server_config*) ap_get_module_config(cmd->server->module_config, &IP2Proxy_module);
	
	if(!config) 
		return NULL;
		
	config->dbFile = apr_pstrdup(cmd->pool, dbFile);

	if(config->enabled) {
		config->ip2proxyObj = IP2Proxy_open(config->dbFile);	
		
		if(!config->ip2proxyObj)
			return "Error opening dbFile!";
	}

	return NULL; 
}

static const char* set_ip2proxy_set_mode(cmd_parms* cmd, void* dummy, const char* mode, int arg) {
	ip2proxy_server_config* config = (ip2proxy_server_config*) ap_get_module_config(cmd->server->module_config, &IP2Proxy_module);
	
	if(!config) 
		return NULL;
	
	if(strcmp(mode, "ALL") == 0) 	
		config->setMode = ALL_SET_MODE;

	else if(strcmp(mode, "ENV") == 0) 	
		config->setMode = ENV_SET_MODE;

	else if(strcmp(mode, "NOTES") == 0)
		config->setMode = NOTES_SET_MODE; 	

	else
		return "Invalid mode for IP2ProxySetMode";
	
	return NULL; 
}

static const char* set_ip2proxy_detect_proxy(cmd_parms *cmd, void *dummy, int arg) {
	ip2proxy_server_config* config = (ip2proxy_server_config*) ap_get_module_config(cmd->server->module_config, &IP2Proxy_module);
	
	if(!config) 
		return NULL;
	
	config->detectReverseProxy = arg;
	
	return NULL;
}

static void* ip2proxy_create_svr_conf(apr_pool_t* pool, server_rec* svr) {
	ip2proxy_server_config* svr_cfg = apr_pcalloc(pool, sizeof(ip2proxy_server_config));
	
	svr_cfg->enabled = 0;
	svr_cfg->dbFile = NULL;
	svr_cfg->setMode = ALL_SET_MODE;
	svr_cfg->detectReverseProxy = 0;
	svr_cfg->ip2proxyObj = NULL;
	return svr_cfg ;
}

static const command_rec ip2proxy_cmds[] = {
	AP_INIT_FLAG("IP2ProxyEnable", set_ip2proxy_enable, NULL, OR_FILEINFO, "Turn on mod_ip2proxy"),
	AP_INIT_TAKE1("IP2ProxyDBFile", (const char *(*)()) set_ip2proxy_dbfile, NULL, OR_FILEINFO, "File path to DB file"),
	AP_INIT_TAKE1("IP2ProxySetMode", (const char *(*)()) set_ip2proxy_set_mode, NULL, OR_FILEINFO, "Set scope mode"),
	AP_INIT_TAKE1("IP2ProxyDetectProxy", (const char *(*)()) set_ip2proxy_detect_proxy, NULL, OR_FILEINFO, "Detect reverse proxy headers"),
	{NULL} 
};

static void ip2proxy_register_hooks(apr_pool_t *p) {
	ap_hook_post_read_request(ip2proxy_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(ip2proxy_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

// API hooks
module AP_MODULE_DECLARE_DATA IP2Proxy_module = {
	STANDARD20_MODULE_STUFF, 
	NULL,
	NULL,
	ip2proxy_create_svr_conf,
	NULL,
	ip2proxy_cmds,
	ip2proxy_register_hooks
};

#!/bin/bash
#
#pce-unit-tests.sh
#version="0.0.1"
#define pce_admin_username_email_address and pce_admin_password variables prior to execution
#
#Licensed under the Apache License, Version 2.0 (the "License"); you may not
#use this file except in compliance with the License. You may obtain a copy of
#the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#License for the specific language governing permissions and limitations under
#the License.

#pce-unit-tests.log
echo "pce-unit-tests.sh" 2>&1 | tee pce-unit-tests.log
date 2>&1 | tee --append pce-unit-tests.log

#authenticate
basic_auth_token=$(echo -n "$pce_admin_username_email_address:$pce_admin_password" | base64)
auth_token=$(curl --silent -X POST -H "Authorization: Basic $basic_auth_token" https://$(hostname):8443/api/v2/login_users/authenticate?pce_fqdn=$(hostname) | jq -r '.auth_token' 2>&1 | tee --append pce-unit-tests.log)
login_response=$(curl --silent -H "Authorization: Token token=$auth_token" https://$(hostname):8443/api/v2/users/login 2>&1 | tee --append pce-unit-tests.log)
auth_username=$(echo $login_response | jq -r '.auth_username')
session_token=$(echo $login_response | jq -r '.session_token')

#access_restrictions
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/access_restrictions -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","ips":["10.0.0.0/8"],"enforcement_exclusions":["user_sessions"]}' 2>&1 | tee --append pce-unit-tests.log
access_restrictions_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/access_restrictions | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$access_restrictions_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#service_accounts
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/service_accounts -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","permissions":[{"role":{"href":"/orgs/1/roles/read_only"},"scope":[]}],"api_key":{"expires_in_seconds":7776000}}' 2>&1 | tee --append pce-unit-tests.log
service_accounts_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/service_accounts | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$service_accounts_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#api_keys
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/users/1/api_keys -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":""}' 2>&1 | tee --append pce-unit-tests.log
api_keys_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/users/1/api_keys | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$api_keys_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#async_queries
async_queries_response_href=$(curl --silent -k -X POST -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/traffic_flows/async_queries -H 'content-type: application/json' --data-raw '{"sources":{"include":[[]],"exclude":[]},"destinations":{"include":[[]],"exclude":[]},"services":{"include":[],"exclude":[]},"sources_destinations_query_op":"and","start_date":"'$(date -d "1 hours ago" +"%Y-%m-%dT%H:%M")'","end_date":"'$(date +"%Y-%m-%dT%H:%M")'","policy_decisions":[],"boundary_decisions":[],"max_results":100000,"exclude_workloads_from_ip_list_query":true,"query_name":""}' | jq -r .href 2>&1 | tee --append pce-unit-tests.log)
async_queries_response_href_status=''
while [[ $async_queries_response_href_status != "completed" ]]; do
    sleep 1
    async_queries_response_href_status=$(curl --silent -s -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$async_queries_response_href | jq -r .status 2>&1 | tee --append pce-unit-tests.log)
done
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$async_queries_response_href 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$async_queries_response_href/download 2>&1 | tee --append pce-unit-tests.log

#auth_security_principals
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/users -X POST -H 'content-type: application/json' --data-raw '{"full_name":"unit_test","username":"unit_test@pce.local","type":"local"}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/auth_security_principals -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test@pce.local","display_name":"unit_test","type":"user"}' 2>&1 | tee --append pce-unit-tests.log
auth_security_principals_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/auth_security_principals | jq -r '.[] | select(.name=="unit_test@pce.local") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/permissions -X POST -H 'content-type: application/json' --data-raw '{"scope":[],"role":{"href":"/orgs/1/roles/read_only"},"auth_security_principal":{"href":"'$auth_security_principals_response_href'"}}' 2>&1 | tee --append pce-unit-tests.log
permissions_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/permissions | jq -r '.[] | select(.auth_security_principal.href=="'$auth_security_principals_response_href'") | .href' 2>&1 | tee --append pce-unit-tests.log)
users_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/users | jq -r '.[] | select(.username=="unit_test@pce.local") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$permissions_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$auth_security_principals_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$users_response_href/local_profile -X DELETE 2>&1 | tee --append pce-unit-tests.log

#password_policy
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/authentication_settings/password_policy -X PUT -H 'content-type: application/json' --data-raw '{"history_count":10}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/authentication_settings/password_policy | jq 2>&1 | tee --append pce-unit-tests.log

#container_clusters
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/container_clusters -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":""}' 2>&1 | tee --append pce-unit-tests.log
container_clusters_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/container_clusters | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$container_clusters_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#core_service_types
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/core_service_types 2>&1 | tee --append pce-unit-tests.log

#database_metrics
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/traffic_flows/database_metrics | jq 2>&1 | tee --append pce-unit-tests.log

#detected_core_services
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/detected_core_services 2>&1 | tee --append pce-unit-tests.log

#discovered_virtual_servers
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/discovered_virtual_servers 2>&1 | tee --append pce-unit-tests.log

#events
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/events 2>&1 | tee --append pce-unit-tests.log

#firewall_settings
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/active/firewall_settings | jq 2>&1 | tee --append pce-unit-tests.log

#health
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/health 2>&1 | tee --append pce-unit-tests.log

#ip_lists
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/ip_lists -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","ip_ranges":[{"from_ip":"1.1.1.1"}],"fqdns":[]}' 2>&1 | tee --append pce-unit-tests.log
ip_lists_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/ip_lists | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"ip_lists":[{"href":"'$ip_lists_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$ip_lists_response_href -X PUT -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","ip_ranges":[],"fqdns":[{"fqdn":"one.one.one.one"}]}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"ip_lists":[{"href":"'$ip_lists_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$ip_lists_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"ip_lists":[{"href":"'$ip_lists_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log

#jobs
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/jobs 2>&1 | tee --append pce-unit-tests.log

#kubernetes_workloads
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/kubernetes_workloads 2>&1 | tee --append pce-unit-tests.log

#labels
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/labels -X POST -H 'content-type: application/json' --data-raw '{"value":"unit_test","key":"app"}' 2>&1 | tee --append pce-unit-tests.log
labels_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/labels | jq -r '.[] | select(.value=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$labels_response_href -X PUT -H 'content-type: application/json' --data-raw '{"value":"unit_test_alfa"}' 2>&1 | tee --append pce-unit-tests.log

#label_groups
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/label_groups -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","key":"app"}' 2>&1 | tee --append pce-unit-tests.log
label_groups_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/label_groups | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$label_groups_response_href -X PUT -H 'content-type: application/json' --data-raw '{"labels":[{"href":"'$labels_response_href'"}],"sub_groups":[]}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$label_groups_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$labels_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#ldap_configs
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/authentication_settings/ldap_configs 2>&1 | tee --append pce-unit-tests.log

settings
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings | jq 2>&1 | tee --append pce-unit-tests.log

#optional_features
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/optional_features | jq 2>&1 | tee --append pce-unit-tests.log

#settings/events
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/events | jq 2>&1 | tee --append pce-unit-tests.log

#pairing_profiles
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/pairing_profiles -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","enforcement_mode":"visibility_only","visibility_level":"flow_summary","allowed_uses_per_key":"unlimited","key_lifespan":"unlimited","app_label_lock":true,"env_label_lock":true,"loc_label_lock":true,"role_label_lock":true,"enforcement_mode_lock":true,"visibility_level_lock":true,"enabled":true,"ven_type":"server"}' 2>&1 | tee --append pce-unit-tests.log
pairing_profiles_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/pairing_profiles | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$pairing_profiles_response_href -X PUT -H 'content-type: application/json' --data-raw '{"description":"unit_test"}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$pairing_profiles_response_href/pairing_key -X POST -H 'content-type: application/json' --data-raw '{}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$pairing_profiles_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#reports
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/reports | jq 2>&1 | tee --append pce-unit-tests.log

#report_schedules
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/report_schedules | jq 2>&1 | tee --append pce-unit-tests.log

#settings/reports
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/reports | jq 2>&1 | tee --append pce-unit-tests.log

#report_templates
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/report_templates | jq 2>&1 | tee --append pce-unit-tests.log

#roles
roles_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/roles | jq -r '.[0].href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$roles_response_href 2>&1 | tee --append pce-unit-tests.log

#Root Level Methods
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/node_available 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/product_version 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/noop 2>&1 | tee --append pce-unit-tests.log

#rulesets and rules
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/rule_sets -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","scopes":[[]]}' 2>&1 | tee --append pce-unit-tests.log
rule_sets_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/rule_sets | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$rule_sets_response_href/sec_rules -X POST -H 'content-type: application/json' --data-raw '{"providers":[{"actors":"ams"}],"consumers":[{"actors":"ams"}],"enabled":true,"ingress_services":[{"proto":6,"port":1}],"network_type":"brn","consuming_security_principals":[],"sec_connect":false,"machine_auth":false,"stateless":false,"unscoped_consumers":false,"description":"","use_workload_subnets":[],"resolve_labels_as":{"consumers":["workloads"],"providers":["workloads"]}}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"rule_sets":[{"href":"'$rule_sets_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log
sec_rules_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$rule_sets_response_href/sec_rules | jq -r '.[0].href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$rule_sets_response_href -X PUT -H 'content-type: application/json' --data-raw '{"ip_tables_rules":[],"rules":[]}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"rule_sets":[{"href":"'$rule_sets_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$rule_sets_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"rule_sets":[{"href":"'$rule_sets_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log

#sec_policy
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/pending 2>&1 | tee --append pce-unit-tests.log

#Selective Enforcement Rules
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/enforcement_boundaries 2>&1 | tee --append pce-unit-tests.log

#slbs
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/slbs 2>&1 | tee --append pce-unit-tests.log

#services
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/services -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","service_ports":[{"proto":6,"port":1}]}' 2>&1 | tee --append pce-unit-tests.log
services_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/services | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"services":[{"href":"'$services_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/services/181 -X PUT -H 'content-type: application/json' --data-raw '{"name":"unit_test","description":"","service_ports":[{"proto":6,"port":2}]}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"services":[{"href":"'$services_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/draft/services/181 -X DELETE 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy -X POST -H 'content-type: application/json' --data-raw '{"update_description":"","change_subset":{"services":[{"href":"'$services_response_href'"}]}}' 2>&1 | tee --append pce-unit-tests.log

#service_bindings
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/service_bindings 2>&1 | tee --append pce-unit-tests.log

#support_bundle_requests
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/support_bundle_requests -X POST -H "content-type: application/json" --data-raw '{"include_logs":false}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/support_bundle_requests 2>&1 | tee --append pce-unit-tests.log

#syslog
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/syslog/destinations 2>&1 | tee --append pce-unit-tests.log

#events
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/events?max_results=1 2>&1 | tee --append pce-unit-tests.log

#traffic_collector
traffic_collector_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/traffic_collector -X POST -H 'content-type: application/json' --data-raw '{"action":"aggregate","transmission":"broadcast","data_source":"any","network":"any"}' | jq -r .href 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/traffic_collector 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$traffic_collector_response_href -X PUT -H 'content-type: application/json' --data-raw '{"transmission":"multicast","data_source":"any","network":"any"}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$traffic_collector_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

#trusted_proxy_ips
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/trusted_proxy_ips 2>&1 | tee --append pce-unit-tests.log

#vens
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/vens 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/vens/statistics -X POST -H 'content-type: application/json' --data-raw '{}' 2>&1 | tee --append pce-unit-tests.log

#software/ven/releases
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/software/ven/releases | jq 2>&1 | tee --append pce-unit-tests.log

#virtual_servers
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/active/virtual_servers 2>&1 | tee --append pce-unit-tests.log

#virtual_services
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/sec_policy/active/virtual_services 2>&1 | tee --append pce-unit-tests.log

#settings/workloads
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/settings/workloads | jq 2>&1 | tee --append pce-unit-tests.log

#workloads
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/workloads -X POST -H 'content-type: application/json' --data-raw '{"name":"unit_test","labels":[],"description":"","hostname":"","data_center":"","os_id":"","os_detail":"","public_ip":null,"distinguished_name":"","service_principal_name":null,"interfaces":[],"ignored_interface_names":[]}' 2>&1 | tee --append pce-unit-tests.log
workloads_response_href=$(curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2/orgs/1/workloads | jq -r '.[] | select(.name=="unit_test") | .href' 2>&1 | tee --append pce-unit-tests.log)
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$workloads_response_href -X PUT -H 'content-type: application/json' --data-raw '{"name":"unit_test","labels":[],"description":"","hostname":"","data_center":"","os_id":"","os_detail":"","public_ip":null,"distinguished_name":"","service_principal_name":null,"enforcement_mode":"visibility_only","visibility_level":"flow_summary","interfaces":[{"address":"1.1.1.1","name":"umw"}],"ignored_interface_names":[]}' 2>&1 | tee --append pce-unit-tests.log
curl --silent -k -u $auth_username:$session_token https://$(hostname):8443/api/v2$workloads_response_href -X DELETE 2>&1 | tee --append pce-unit-tests.log

exit 0

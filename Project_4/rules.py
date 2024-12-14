alert tcp 18.219.211.0/24 any -> 172.31.69.0/24 80
(
	msg:"DdoS";
	detection_filter: track by_dst, count 500, seconds 1;
	sid:1000001;
	rev:1;
		
)

alert tcp 13.58.98.0/24 any -> 172.31.69.0/24 22 
(
	msg:"Bruteforce";
	detection_filter: track by_dst, count 300, seconds 1;
    sid:1000002;
	rev:1;
)

alert tcp 18.218.115.60 any -> 172.31.69.28 80 (
	msg:"WebAttack";
	flow:to_server,established;
	pcre:"/DVWA\/login\.php/"; 
	sid:1000003;
	rev:1;
)

alert http 172.31.69.0/24 any -> 18.219.211.138 8080
(
    msg:"Botnet";	
	http_method; content: "POST";
	http_uri; content: "/api/Administrator";
    sid:1000004;
    rev:1;
)
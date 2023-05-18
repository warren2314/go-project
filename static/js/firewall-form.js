document.getElementById('firewall-form').addEventListener('submit', function(event) {
    event.preventDefault();

    let ipaddress1 = document.getElementById('ipaddress1').value;
    let ipaddress2 = document.getElementById('ipaddress2').value;
    let ipaddress3 = document.getElementById('ipaddress3').value;
    let ipaddress4 = document.getElementById('ipaddress4').value;
    let protocol = document.getElementById('protocol').value;
    let port = document.getElementById('port').value;
    let action = document.getElementById('action').value;

    let ipaddress = ipaddress1 + '.' + ipaddress2 + '.' + ipaddress3 + '.' + ipaddress4;

    let data = {
        'Protocol': protocol,
        'IpAddress': ipaddress,
        'Port': port,
        'Action': action
    };

    fetch('/api/configure_firewall', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    })
        .then(response => response.json())
        .then(data => {
            console.log('Success:', data);
        })
        .catch((error) => {
            console.error('Error:', error);
        });
});